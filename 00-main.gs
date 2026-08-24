/**
 * Orquestador principal de Auditorías de Seguridad para Google Workspace.
 * Centraliza la inicialización de contexto y ejecución polimórfica.
 */

// =============================================================================
// MOTOR Y HELPER COMÚN DE EJECUCIÓN
// =============================================================================

/**
 * Inicializa el contexto global en RAM (Censo, Diccionario OU, Políticas, AuthService).
 * @param {AuthService} auth
 * @param {string} customerId
 * @param {Object} extraContext
 * @return {Object} globalContext
 */
function _crearContextoGlobalAuditoria(auth, customerId, extraContext = {}) {
  const censoWrapper = new CensusStateWrapper();
  censoWrapper.buildAndStoreCensus(auth, customerId);
  const censo = censoWrapper.getCensus();
  CELParserEngine.ouIdToPathMap = censoWrapper.getOuMap();
  
  const policyQuery = new GlobalPolicyExtractor(auth, customerId);
  const politicas = policyQuery.fetchTree();
  
  return {
    census: censo,
    policies: politicas,
    auth: auth,
    ...extraContext
  };
}

/**
 * Ejecutor genérico para cualquier módulo de auditoría.
 * Centraliza la inicialización, feedback en UI, Facade, bucle polimórfico, semáforo y control de errores.
 */
function _ejecutarModuloAuditoria({
  tituloModulo,
  mensajeDialogo,
  mensajeExito,
  extraContextBuilder = null,
  estrategiasBuilder
}) {
  const ui = SpreadsheetApp.getUi();
  try {
    const auth = new AuthService();
    const customerId = auth.getCustomerId();

    const extraContext = typeof extraContextBuilder === 'function' 
      ? extraContextBuilder(auth, customerId) 
      : {};
      
    const globalContext = _crearContextoGlobalAuditoria(auth, customerId, extraContext);
    const errorCollector = new AuditErrorCollector();
    const auditor = new SecurityAuditorFacade(auth, globalContext, errorCollector);

    const estrategias = estrategiasBuilder(auth, customerId, globalContext) || [];
    if (estrategias.length === 0) {
      ui.alert(`El módulo de ${tituloModulo} está listo, pero aún no tiene métricas asignadas.`);
      return;
    }

    estrategias.forEach(estrategia => auditor.addStrategy(estrategia));

    ui.showModelessDialog(
      HtmlService.createHtmlOutput(`⏳ ${mensajeDialogo}`),
      "Estado"
    );

    const resultados = auditor.ejecutarTodo();

    // Bucle Polimórfico Puro para escribir en el Sheets
    resultados.forEach(res => {
      const estrategiaResponsable = estrategias.find(e => e.name === res.name);
      if (estrategiaResponsable && res) {
        estrategiaResponsable.writeToSheet(res);
      }
    });

    generarResumenSemaforo();

    // Consolidado y emisión de alertas por correo
    if (errorCollector.hasErrors()) {
      AlertService.sendErrorDigest(tituloModulo, errorCollector.getErrors());
      Logger.log(errorCollector.getSummary());
      ui.alert(`⚠️ ${mensajeExito}\n\nNota: Se detectaron ${errorCollector.getErrors().length} incidencias/errores en el módulo. Se ha enviado un consolidado detallado a jsuarez@apisas.com.`);
    } else {
      ui.alert(`✅ ${mensajeExito}`);
    }

  } catch (error) {
    Logger.log(`Error en auditoría de ${tituloModulo}: ${error.stack || error.message}`);
    ui.alert(`❌ Error: ${error.message}`);
  }
}

// =============================================================================
// MÓDULOS DE AUDITORÍA ESPECÍFICOS (PUNTOS DE ENTRADA DESDE UI)
// =============================================================================

/**
 * Orquestador principal para la auditoría de Identidad y Autenticación
 */
function AuditoriaIdentidadIdentificacion() {
  _ejecutarModuloAuditoria({
    tituloModulo: "Identidad y Autenticación",
    mensajeDialogo: "Procesando auditoría de identidad y autenticación, puede tomar algunos segundos...",
    mensajeExito: "Auditoría de identidad y autenticación completada con éxito.",
    estrategiasBuilder: (auth, customerId) => {
      const zeroTrustPolicyId = auth.getZeroTrustPolicyId();
      return [
        new SsoAuditStrategy(customerId),
        new StrongPasswordPolicyStrategy(customerId),
        new PasswordReusePolicyStrategy(customerId),
        new TwoStepVerificationEnrollmentPolicyStrategy(customerId),
        new TwoStepVerificationCounter(customerId),
        new TwoStepVerificationEnforcementPolicyStrategy(customerId),
        new AdminTwoStepVerificationEnforcementStrategy(customerId),
        new TrustedDevice2SVPolicyStrategy(customerId),
        new Allowed2SVMethodsPolicyStrategy(customerId),
        new GracePeriod2SVPolicyStrategy(customerId),
        new TwoStepVerificationSignInCodePolicyStrategy(customerId),
        new SuperAdminAccountRecoveryPolicyStrategy(customerId),
        new UserAccountRecoveryPolicyStrategy(customerId),
        new EmployeeIdLoginChallengePolicyStrategy(customerId),
        new SuperAdminSecurityStrategy(),
        new ContextAwareAccessStrategy(zeroTrustPolicyId),
        new ExternalProvisioningStrategy(),
        new ManualUserAuditStrategy(),
        new DeprovisioningAuditStrategy(),
        new SlaOffboardingAuditStrategy(),
        new PostSsoLoginPolicyStrategy(customerId),
        new AdvancedProtectionPolicyStrategy(customerId)
      ];
    }
  });
}

/**
 * Orquestador principal para la auditoría de Administración
 */
function AuditoriaAdministracion() {
  _ejecutarModuloAuditoria({
    tituloModulo: "Administración",
    mensajeDialogo: "Procesando auditoría de administración, puede tomar algunos segundos...",
    mensajeExito: "Auditoría de administración completada con éxito.",
    estrategiasBuilder: (auth, customerId) => [
      new GroupsAdminRoleAssignmentStrategy(customerId, auth.getGroupsAdminRoleId()),
      new UserManagementAdminRoleStrategy(customerId, auth.getUserAdminRoleId()),
      new HelpDeskAdminRoleStrategy(customerId, auth.getHelpDeskAdminRoleId()),
      new AndroidAdminRoleStrategy(customerId, auth.getAndroidAdminRoleId()),
      new GoogleVoiceAdminRoleStrategy(customerId, auth.getVoiceAdminRoleId()),
      new MobileAdminRoleStrategy(customerId, auth.getMobileAdminRoleId()),
      new ServicesAdminRoleStrategy(customerId, auth.getServicesAdminRoleId()),
      new VaultSuperAdminLicenseAuditStrategy(customerId, auth.getSuperAdminRoleId()),
      new VaultAccessControlStrategy(customerId)
    ]
  });
}

/**
 * Orquestador principal para la auditoría de Aplicaciones Externas (OAuth, Marketplace, etc.)
 */
function AuditoriasAppsExternas() {
  _ejecutarModuloAuditoria({
    tituloModulo: "Aplicaciones Externas",
    mensajeDialogo: "Procesando auditoría de aplicaciones externas, puede tomar algunos segundos...",
    mensajeExito: "Auditoría de aplicaciones externas completada con éxito.",
    estrategiasBuilder: (auth, customerId) => [
      new GoogleServicesApiControlStrategy(customerId),
      new GoogleCloudApiControlStrategy(customerId),
      new UnconfiguredAppsStrategy(customerId),
      new InternalAppsTrustStrategy(customerId),
      new CustomUserMessageApiStrategy(customerId),
      new DwdTokenRequestAuditStrategy(),
      new ServiceAccountKeyAgeStrategy(auth.getGcpProjectId(), auth.getGcpServiceAccountEmail()),
      new MarketplaceInstallPolicyStrategy(customerId),
      new AdminAppInstallEventStrategy(),
      new MarketplaceAllowlistStrategy(customerId),
      new AccessedAppsStrategy(customerId)
    ]
  });
}

/**
 * Orquestador principal para la auditoría de configuraciones de Correo Electrónico (Gmail)
 */
function AuditoriasEmail() {
  _ejecutarModuloAuditoria({
    tituloModulo: "Correo Electrónico",
    mensajeDialogo: "Procesando auditoría de correo electrónico, puede tomar algunos segundos...",
    mensajeExito: "Auditoría de correo electrónico completada con éxito.",
    estrategiasBuilder: (auth, customerId) => {
      const domain = auth.getDomain();
      return [
        new GmailConfidentialModeStrategy(customerId),
        new GmailImapAccessStrategy(customerId),
        new WorkspaceSyncForOutlookStrategy(customerId),
        new GmailAutoForwardingStrategy(customerId),
        new GmailImageProxyBypassStrategy(customerId),
        new GmailPerUserOutboundGatewayStrategy(customerId),
        new GmailLinksAndExternalImagesStrategy(customerId),
        new GmailAttachmentSafetyStrategy(customerId),
        new GmailSpoofingAndAuthenticationStrategy(customerId),
        new GmailAttachmentSafetyId073Strategy(customerId),
        new GmailSpamFilterIpAllowlistStrategy(customerId),
        new GmailSpamOverrideListsStrategy(customerId),
        new GmailEnhancedPreDeliveryScanningStrategy(customerId),
        new GmailBlockedSenderListsStrategy(customerId),
        new GmailLinksExternalImagesSecurityStrategy(customerId),
        new GmailContentComplianceStrategy(customerId),
        new GmailAttachmentComplianceStrategy(customerId),
        new TestDomainAliasStrategy(customerId),
        new SpfRecordAuditStrategy(domain),
        new DkimRecordAuditStrategy(domain),
        new DmarcRecordAuditStrategy(domain),
        new MtaStsRecordAuditStrategy(domain),
        new GmailSmimeEncryptionStrategy(customerId),
        new GmailSmimeCertificateManagementStrategy(customerId),
        new GmailWebOfflineStrategy(customerId),
        new GmailSecuritySandboxStrategy(customerId),
        new GmailInboundGatewayStrategy(customerId),
        new GmailAggressiveSpamStrategy(customerId),
        new GmailBypassInternalSpamStrategy(customerId),
        new GmailRequireAuthApprovedSendersStrategy(customerId),
        new GmailOcrAttachmentsStrategy(customerId),
        new GmailRestrictDeliveryStrategy(customerId),
        new GmailTlsComplianceStrategy(customerId),
        new GmailOutboundGatewayStrategy(customerId),
        new GmailRoutingRulesStrategy(customerId),
        new GmailSmtpRelayStrategy(customerId)
      ];
    }
  });
}

/**
 * Orquestador principal para la auditoría de Google Drive
 */
function AuditoriaDrive() {
  _ejecutarModuloAuditoria({
    tituloModulo: "Google Drive",
    mensajeDialogo: "Procesando auditoría de Google Drive, puede tomar algunos segundos...",
    mensajeExito: "Auditoría de Google Drive completada con éxito.",
    estrategiasBuilder: (auth, customerId) => [
      new DriveExternalSharingModeStrategy(customerId),
      new DriveAllowlistedDomainsSharingStrategy(customerId),
      new DriveWarnExternalSharingStrategy(customerId),
      new DriveAllowNonGoogleInvitesStrategy(customerId),
      new DriveAllowPublishingFilesStrategy(customerId),
      new DriveAllowReceivingExternalFilesStrategy(customerId),
      new DriveAccessCheckerSuggestionsStrategy(customerId),
      new DriveTargetAudiencesStrategy(customerId, auth),
      new DriveSharedDriveDistributingContentStrategy(customerId),
      new DrivePreventSharedDriveCreationStrategy(customerId),
      new DriveAllowManagersToOverrideStrategy(customerId),
      new DriveAllowExternalUserAccessStrategy(customerId),
      new DriveAllowNonMemberAccessStrategy(customerId),
      new DriveAllowedPartiesDownloadPrintCopyStrategy(customerId),
      new DriveDefaultFileAccessStrategy(customerId),
      new DriveSdkApiAccessStrategy(customerId),
      new DriveForDesktopAuthorizedDevicesStrategy(customerId),
      new WorkspaceMarketplaceAppsAllowlistStrategy(customerId),
      new DataLossPreventionRulesStrategy(customerId)
    ]
  });
}

/**
 * Orquestador principal para la auditoría de Servicios Adicionales (Calendar, etc.)
 */
function AuditoriaServiciosAdicionales() {
  _ejecutarModuloAuditoria({
    tituloModulo: "Servicios Adicionales",
    mensajeDialogo: "Procesando auditoría de servicios adicionales, puede tomar algunos segundos...",
    mensajeExito: "Auditoría de Servicios Adicionales completada con éxito.",
    extraContextBuilder: (auth, customerId) => {
      const groupsList = [];
      try {
        const adminEmail = auth.getCurrentUserEmail();
        const groupsHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/admin.directory.group.readonly"
        ]);
        let groupPageToken = null;
        do {
          let groupsUrl = `https://admin.googleapis.com/admin/directory/v1/groups?customer=${encodeURIComponent(customerId)}&maxResults=200`;
          if (groupPageToken) groupsUrl += `&pageToken=${encodeURIComponent(groupPageToken)}`;
          const groupsResponse = UrlFetchApp.fetch(groupsUrl, {
            method: "get",
            headers: { ...groupsHeader, "Cache-Control": "no-cache" },
            muteHttpExceptions: true
          });
          const groupsJson = JSON.parse(groupsResponse.getContentText());
          if (groupsJson.groups) {
            groupsList.push(...groupsJson.groups);
          }
          groupPageToken = groupsJson.nextPageToken || null;
        } while (groupPageToken);
        Logger.log(`[MAIN] Se cargaron ${groupsList.length} grupos del directorio vía DWD.`);
      } catch (e) {
        Logger.log("[WARN] Error al obtener grupos del directorio vía DWD: " + e.message);
      }
      return { groups: groupsList };
    },
    estrategiasBuilder: (auth, customerId) => [
      new CalendarPrimaryExternalSharingStrategy(customerId),
      new CalendarExternalInvitationsStrategy(customerId),
      new CalendarSecondaryExternalSharingStrategy(customerId),
      new CalendarInteroperability(customerId),
      new ContactsExternalDirectorySharingStrategy(customerId),
      new GroupsSharingExternalMembersStrategy(customerId),
      new GroupsViewTopicsDefaultAccessStrategy(customerId),
      new GroupsCreateGroupsAccessStrategy(customerId),
      new GroupsOwnersAllowExternalMembersStrategy(customerId),
      new GroupsSettingsAccessStrategy(customerId),
      new GroupsSpamModerationStrategy(customerId),
      new SitesCreationModificationStrategy(customerId),
      new SitesDriveExternalSharingStrategy(customerId),
      new ChatHistorySettingsStrategy(customerId),
      new ChatExternalWarningStrategy(customerId),
      new ChatAllowExternalChatsStrategy(customerId),
      new ChatFileSharingStrategy(customerId),
      new GoogleTakeoutStatusStrategy(customerId),
      new LookerDataStudioSharingStrategy(customerId),
      new AdditionalServicesToSAuditStrategy(customerId)
    ]
  });
}

/**
 * Orquestador principal para la auditoría gestión de dispositivos (windows, etc.)
 */
function AuditoriaGestionDispositivos() {
  _ejecutarModuloAuditoria({
    tituloModulo: "Gestión de Dispositivos",
    mensajeDialogo: "Procesando auditoría de gestión de dispositivos, puede tomar algunos segundos...",
    mensajeExito: "Auditoría de gestión de dispositivos completada con éxito.",
    estrategiasBuilder: (auth, customerId) => [
      new MobileDeviceApprovalStrategy(customerId),
      new AndroidMobileSyncStrategy(customerId),
      new IosMobileSyncStrategy(customerId),
      new ActiveSyncMobileSyncStrategy(customerId),
      new AppleDeviceEnrollmentStrategy(customerId),
      new AppleAppsImapStrategy(customerId),
      new BasicPasswordComplianceStrategy(customerId),
      new StrongPasswordComplianceStrategy(customerId),
      new DeviceWipePolicyStrategy(customerId),
      new ManagedIosAppsStrategy(customerId),
      new ManagedAndroidAppsStrategy(customerId),
      new AndroidWorkProfileStrategy(customerId),
      new ManagedAppsDataSharingStrategy(customerId),
      new UnmanagedAppsDataSharingStrategy(customerId)
    ]
  });
}

/**
 * Orquestador principal para la auditoría de Gestión de Navegadores (Chrome)
 */
function AuditoriaGestionNavegador() {
  _ejecutarModuloAuditoria({
    tituloModulo: "Gestión de Navegadores Chrome",
    mensajeDialogo: "Procesando auditoría de gestión de navegadores Chrome, puede tomar algunos segundos...",
    mensajeExito: "Auditoría de gestión de navegadores Chrome completada con éxito.",
    estrategiasBuilder: (auth, customerId) => [
      new ChromeCloudEnrollmentStrategy(customerId),
      new ChromeMachinePolicyStrategy(customerId),
      new ChromeBrowserSigninStrategy(customerId),
      new ChromePasswordManagerStrategy(customerId),
      new ChromeRendererCodeIntegrityStrategy(customerId),
      new ChromeAdvancedProtectionStrategy(customerId),
      new ChromeSafeBrowsingLevelStrategy(customerId),
      new ChromeDownloadRestrictionsStrategy(customerId),
      new ChromePasswordAlertStrategy(customerId),
      new ChromeEndpointVerificationStrategy(customerId),
      new ChromeComponentUpdatesStrategy(customerId),
      new ChromeUpdatePolicyOverrideStrategy(customerId),
      new ChromePolicyPrecedenceStrategy(customerId),
      new ChromeSyncSettingsCbcmStrategy(customerId)
    ]
  });
}

/**
 * Orquestador principal para la auditoría de Preparar y supervisar
 */
function AuditoriaPrepararSupervisar() {
  _ejecutarModuloAuditoria({
    tituloModulo: "Preparar y Supervisar",
    mensajeDialogo: "Procesando auditoría de preparar y supervisar, puede tomar algunos segundos...",
    mensajeExito: "Auditoría de preparar y supervisar completada con éxito.",
    estrategiasBuilder: (auth, customerId) => [
      new SecurityCenterUsageStrategy(customerId),
      new SiemIntegrationStrategy(customerId),
      new BigQueryLogExportStrategy(customerId),
      new WorkspaceReportsBigQueryExportStrategy(customerId),
      new WorkspaceSecurityRulesStrategy(customerId),
      new SecurityActivityRulesStrategy(customerId),
      new DomainVerificationStrategy(customerId)
    ]
  });
}

/**
 * Orquestador principal para la auditoría de Informes e Investigación
 */
function AuditoriaInformeInvestigacion() {
  _ejecutarModuloAuditoria({
    tituloModulo: "Informes e Investigación",
    mensajeDialogo: "Procesando auditoría de informes e investigación, puede tomar algunos segundos...",
    mensajeExito: "Auditoría de informes e investigación completada con éxito.",
    estrategiasBuilder: (auth, customerId) => [
      new WorkspaceReportsBigQueryExportCrossAuditStrategy(customerId),
      new SecurityInvestigationToolUsageStrategy(customerId),
      new RequireReviewerBulkActionsStrategy(customerId),
      new ViewSensitiveContentStrategy(customerId),
      new RequireActionJustificationStrategy(customerId),
      new SecurityReportingRulesStrategy(customerId),
      new SecurityActivityRulesAutomationStrategy(customerId)
    ]
  });
}

/**
 * Función dedicada únicamente a ejecutar las pruebas exploratorias
 */
function ProbarApis() {
  const ui = SpreadsheetApp.getUi();
  ui.showModelessDialog(
    HtmlService.createHtmlOutput("⏳ Ejecutando pruebas exploratorias. Revisa los logs en unos momentos."), 
    "Ejecutando pruebas de Chrome"
  );
  
  try {
    const tester = new ChromeApiTester();
    tester.runAllTests();
    ui.alert("✅ Pruebas de APIs de Chrome completadas. Por favor, abre 'Ver -> Registro de ejecución' para examinar los resultados detallados.");
  } catch (error) {
    Logger.log("Error crítico en la ejecución de pruebas de Chrome: " + error.stack);
    ui.alert("❌ Error crítico: " + error.message);
  }
}
