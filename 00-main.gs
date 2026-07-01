/**
 * Orquestador principal para la auditoría de Identidad y Autenticación
 */

function AuditoriaIdentidadIdentificacion() {
  const ui = SpreadsheetApp.getUi();
  
  try {
    const auth = new AuthService();
    // OAuth config
    const userEmail = auth.getCurrentUserEmail();
    const authHeader = auth.getAuthHeader();
    const zeroTrustPolicyId = auth.getZeroTrustPolicyId();
    const customerId = auth.getCustomerId();
    //censo de usuarios para policy query
    const censoWrapper = new CensusStateWrapper();
    censoWrapper.buildAndStoreCensus(auth, customerId);
    const censo = censoWrapper.getCensus();
    // Inyectar diccionario OU ID → Path al motor CEL para resolución de OUs
    CELParserEngine.ouIdToPathMap = censoWrapper.getOuMap();
    const policyQuery = new GlobalPolicyExtractor(auth, customerId);
    const politicas = policyQuery.fetchTree();
    const globalContext = {
      census: censo,
      policies: politicas,
      auth: auth
    };
    const auditor = new SecurityAuditorFacade(auth, globalContext);

    // 1. Instanciamos las estrategias en un arreglo local para retener su referencia
    const estrategias = [
      new SsoAuditStrategy(customerId), //1,2
      new StrongPasswordPolicyStrategy(customerId),//3
      new PasswordReusePolicyStrategy(customerId), //4
      new TwoStepVerificationEnrollmentPolicyStrategy(customerId), //7
      new TwoStepVerificationCounter(customerId), //8        
      new TwoStepVerificationEnforcementPolicyStrategy(customerId), //9
      new AdminTwoStepVerificationEnforcementStrategy(customerId), //10
      new TrustedDevice2SVPolicyStrategy(customerId), //11
      new Allowed2SVMethodsPolicyStrategy(customerId), //12
      new GracePeriod2SVPolicyStrategy(customerId), //13
      new TwoStepVerificationSignInCodePolicyStrategy(customerId), // 14
      new SuperAdminAccountRecoveryPolicyStrategy(customerId), //16
      new UserAccountRecoveryPolicyStrategy(customerId), //17
      new EmployeeIdLoginChallengePolicyStrategy(customerId), //19
      

      new SuperAdminSecurityStrategy(), //24
      new ContextAwareAccessStrategy(zeroTrustPolicyId), //25
      new ExternalProvisioningStrategy(), //28
      new ManualUserAuditStrategy(), //29
      new DeprovisioningAuditStrategy(), //30
      new SlaOffboardingAuditStrategy(), //31
      
      // Integrando estrategias previamente no llamadas
      new PostSsoLoginPolicyStrategy(customerId),
      new AdvancedProtectionPolicyStrategy(customerId),
      new AdvancedProtectionPolicyCodesStrategy(customerId),
      
      /**
      new AdvancedProtectionPolicyStrategy(customerId), //24      
      new EmployeeIdStrategy(), //22
      new UsuarioConfiguracionAvanzadaStrategy(), //25      
      new ContextAwareAccessStrategy(zeroTrustPolicyId), //27
      new AuditTokens(userEmail), //7, 8
      new PasswordManagerStrategy(), //17
      new PostSsoLoginPolicyStrategy(customerId), //20      
      */       
    ];
  // 2. Agregamos las estrategias al auditor
    estrategias.forEach(estrategia => auditor.addStrategy(estrategia));

    ui.showModelessDialog(HtmlService.createHtmlOutput("⏳ Procesando auditoría de identidad y autenticación, puede tomar algunos segundos"), "Estado");
    
    // 3. Ejecutamos las APIs (La Facade ahora se encarga de pausar automáticamente)
    const resultados = auditor.ejecutarTodo();
    
    generarResumenSemaforo();
    ui.alert("✅ Auditoría de identidad y autenticación completada con éxito.");

  } catch (error) {
    Logger.log("Error en auditoría: " + error.stack);
    ui.alert("❌ Error: " + error.message);
  }
}
  
/**
 * Orquestador principal para la auditoría de Administración
 */
function AuditoriaAdministracion() {
  const ui = SpreadsheetApp.getUi();
  try {
    const auth = new AuthService();
    const customerId = auth.getCustomerId();
    
    // 0. Inicializar contexto global en RAM (Censo de usuarios con roles y Políticas)
    const censoWrapper = new CensusStateWrapper();
    censoWrapper.buildAndStoreCensus(auth, customerId);
    const censo = censoWrapper.getCensus();
    // Inyectar diccionario OU ID → Path al motor CEL para resolución de OUs
    CELParserEngine.ouIdToPathMap = censoWrapper.getOuMap();
    
    const policyQuery = new GlobalPolicyExtractor(auth, customerId);
    const politicas = policyQuery.fetchTree();
    
    const globalContext = {
      census: censo,
      policies: politicas,
      auth: auth
    };
    
    const auditor = new SecurityAuditorFacade(auth, globalContext);

    const superAdminRoleId = auth.getSuperAdminRoleId(); 
    const groupsAdminRoleId = auth.getGroupsAdminRoleId();
    const userAdminRoleId = auth.getUserAdminRoleId();
    const helpDeskRoleId = auth.getHelpDeskAdminRoleId();
    const androidAdminRoleId = auth.getAndroidAdminRoleId();
    const voiceAdminRoleId = auth.getVoiceAdminRoleId();
    const mobileAdminRoleId = auth.getMobileAdminRoleId();
    const servicesAdminRoleId = auth.getServicesAdminRoleId();

    // 1. Instanciamos las estrategias exclusivas de Administración
    const estrategias = [
      new GroupsAdminRoleAssignmentStrategy(customerId, groupsAdminRoleId),
      new UserManagementAdminRoleStrategy(customerId, userAdminRoleId),
      new HelpDeskAdminRoleStrategy(customerId, helpDeskRoleId),
      new AndroidAdminRoleStrategy(customerId, androidAdminRoleId),
      new GoogleVoiceAdminRoleStrategy(customerId, voiceAdminRoleId),
      new MobileAdminRoleStrategy(customerId, mobileAdminRoleId),
      new ServicesAdminRoleStrategy(customerId, servicesAdminRoleId),
      new VaultSuperAdminLicenseAuditStrategy(customerId, superAdminRoleId),
      new VaultAccessControlStrategy(customerId)
    ];

    // 2. Agregamos las estrategias al auditor
    estrategias.forEach(estrategia => auditor.addStrategy(estrategia));

    ui.showModelessDialog(HtmlService.createHtmlOutput("⏳ Procesando auditoría de administración, puede tomar algunos segundos..."), "Estado");
    
    // 3. Ejecutamos las APIs (La Facade se encarga de pausar automáticamente para proteger la cuota)
    const resultados = auditor.ejecutarTodo();
    
    // 4. Bucle Polimórfico Puro para escribir en el Sheets
    resultados.forEach(res => {
      const estrategiaResponsable = estrategias.find(e => e.name === res.name);
      
      if (estrategiaResponsable && res) {
        estrategiaResponsable.writeToSheet(res); 
      }
    });
    generarResumenSemaforo();
    ui.alert("✅ Auditoría de administración completada con éxito.");

  } catch (error) {
    Logger.log("Error en auditoría de administración: " + error.stack);
    ui.alert("❌ Error: " + error.message);
  }
}

/**
 * Orquestador principal para la auditoría de Aplicaciones Externas (OAuth, Marketplace, etc.)
 */
function AuditoriasAppsExternas() {
  const ui = SpreadsheetApp.getUi();
  
  try {
    const auth = new AuthService();
    
    // Extracción de variables comunes que podríamos necesitar
    const customerId = auth.getCustomerId();
    const authHeader = auth.getAuthHeader();
    const gcpProjectId = auth.getGcpProjectId();
    const gcpServiceAccount = auth.getGcpServiceAccountEmail();

    // 0. Inicializar contexto global en RAM (Censo de usuarios con roles y Políticas)
    // Esto es vital para las estrategias que utilizan evaluateInMemory()
    const censoWrapper = new CensusStateWrapper();
    censoWrapper.buildAndStoreCensus(auth, customerId);
    const censo = censoWrapper.getCensus();
    // Inyectar diccionario OU ID → Path al motor CEL para resolución de OUs
    CELParserEngine.ouIdToPathMap = censoWrapper.getOuMap();
    
    const policyQuery = new GlobalPolicyExtractor(auth, customerId);
    const politicas = policyQuery.fetchTree();
    
    const globalContext = {
      census: censo,
      policies: politicas,
      auth: auth
    };
    
    const auditor = new SecurityAuditorFacade(auth, globalContext);

    // 1. Instanciamos las estrategias exclusivas de Apps Externas
    const estrategias = [      
      new GoogleServicesApiControlStrategy(customerId),      
      new GoogleCloudApiControlStrategy(customerId),
      new UnconfiguredAppsStrategy(customerId),
      new InternalAppsTrustStrategy(customerId),
      new CustomUserMessageApiStrategy(customerId),
      new DwdTokenRequestAuditStrategy(),
      new ServiceAccountKeyAgeStrategy(gcpProjectId, gcpServiceAccount),
      new MarketplaceInstallPolicyStrategy(customerId),
      new AdminAppInstallEventStrategy(),
      new MarketplaceAllowlistStrategy(customerId),
      new AccessedAppsStrategy(customerId)
    ];

    // 2. Agregamos las estrategias al auditor
    estrategias.forEach(estrategia => auditor.addStrategy(estrategia));

    // Si no hay estrategias aún, avisamos y salimos para no ejecutar en vacío
    if (estrategias.length === 0) {
      ui.alert("El módulo de Aplicaciones Externas está listo, pero aún no tiene métricas asignadas.");
      return;
    }

    ui.showModelessDialog(HtmlService.createHtmlOutput("⏳ Procesando auditoría de aplicaciones externas, puede tomar algunos segundos..."), "Estado");
    
    // 3. Ejecutamos las APIs (La Facade se encarga de pausar automáticamente para proteger la cuota)
    const resultados = auditor.ejecutarTodo();
    
    // 4. Bucle Polimórfico Puro para escribir en el Sheets
    resultados.forEach(res => {
      const estrategiaResponsable = estrategias.find(e => e.name === res.name);
      
      if (estrategiaResponsable && res) {
        estrategiaResponsable.writeToSheet(res); 
      }
    });
    generarResumenSemaforo();
    ui.alert("✅ Auditoría de aplicaciones externas completada con éxito.");

  } catch (error) {
    Logger.log("Error en auditoría de apps externas: " + error.stack);
    ui.alert("❌ Error: " + error.message);
  }
}

/**
 * Orquestador principal para la auditoría de configuraciones de Correo Electrónico (Gmail)
 */
function AuditoriasEmail() {
  const ui = SpreadsheetApp.getUi();
  
  try {
    const auth = new AuthService();
    
    // Extracción de variables comunes que podríamos necesitar
    const customerId = auth.getCustomerId();
    const domain = auth.getDomain();

    // 0. Inicializar contexto global en RAM (Censo de usuarios con roles y Políticas)
    // Esto es vital para las estrategias de email que utilizan evaluateInMemory()
    const censoWrapper = new CensusStateWrapper();
    censoWrapper.buildAndStoreCensus(auth, customerId);
    const censo = censoWrapper.getCensus();
    // Inyectar diccionario OU ID → Path al motor CEL para resolución de OUs
    CELParserEngine.ouIdToPathMap = censoWrapper.getOuMap();
    
    const policyQuery = new GlobalPolicyExtractor(auth, customerId);
    const politicas = policyQuery.fetchTree();
    
    const globalContext = {
      census: censo,
      policies: politicas,
      auth: auth
    };
    
    const auditor = new SecurityAuditorFacade(auth, globalContext);

    // 1. Instanciamos las estrategias exclusivas de Correo Electrónico
    const estrategias = [
      
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
      
      // Nuevas 14 estrategias implementadas
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

    // 2. Agregamos las estrategias al auditor
    estrategias.forEach(estrategia => auditor.addStrategy(estrategia));

    // Si no hay estrategias aún, avisamos y salimos para no ejecutar en vacío
    if (estrategias.length === 0) {
      ui.alert("El módulo de Correo Electrónico está listo, pero aún no tiene métricas asignadas.");
      return;
    }

    ui.showModelessDialog(HtmlService.createHtmlOutput("⏳ Procesando auditoría de correo electrónico, puede tomar algunos segundos..."), "Estado");
    
    // 3. Ejecutamos las APIs (La Facade se encarga de pausar automáticamente para proteger la cuota)
    const resultados = auditor.ejecutarTodo();
    
    // 4. Bucle Polimórfico Puro para escribir en el Sheets
    resultados.forEach(res => {
      const estrategiaResponsable = estrategias.find(e => e.name === res.name);
      
      if (estrategiaResponsable && res) {
        estrategiaResponsable.writeToSheet(res); 
      }
    });
    generarResumenSemaforo();
    ui.alert("✅ Auditoría de correo electrónico completada con éxito.");

  } catch (error) {
    Logger.log("Error en auditoría de email: " + error.stack);
    ui.alert("❌ Error: " + error.message);
  }
}
/**
* Orquestador principal para la auditoría de Google Drive
*/
function AuditoriaDrive() {
  const ui = SpreadsheetApp.getUi();
  
  try {
    const auth = new AuthService();
    
    // Extracción de variables comunes que podríamos necesitar
    const customerId = auth.getCustomerId();
    // Obtener el email del usuario actual para pasarlo a estrategias que lo requieran (ej. AuditTokens)
    const userEmail = auth.getCurrentUserEmail();

    // 0. Inicializar contexto global en RAM (Censo de usuarios con roles y Políticas)
    const censoWrapper = new CensusStateWrapper();
    censoWrapper.buildAndStoreCensus(auth, customerId);
    const censo = censoWrapper.getCensus();
    // Inyectar diccionario OU ID → Path al motor CEL para resolución de OUs
    CELParserEngine.ouIdToPathMap = censoWrapper.getOuMap();
    
    const policyQuery = new GlobalPolicyExtractor(auth, customerId);
    const politicas = policyQuery.fetchTree();
    
    const globalContext = {
      census: censo,
      policies: politicas,
      auth: auth
    };
    
    // Instanciamos el facade
    const auditor = new SecurityAuditorFacade(auth, globalContext);

    // --- 1. DEFINICIÓN DE ESTRATEGIAS ---
    // Aquí conectamos cada estrategia con su lógica de negocio.
    const estrategias = [
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
      new DriveForDesktopStrategy(customerId)

    ];

    // --- 2. REGISTRO DE ESTRATEGIAS ---
    estrategias.forEach(estrategia => auditor.addStrategy(estrategia));

    // Si no hay estrategias aún, avisamos y salimos para no ejecutar en vacío
    if (estrategias.length === 0) {
      ui.alert("El módulo de Google Drive está listo, pero aún no tiene métricas asignadas.");
      return;
    }

    // --- 3. EJECUCIÓN ---
    ui.showModelessDialog(HtmlService.createHtmlOutput("⏳ Procesando auditoría de Google Drive, puede tomar algunos segundos..."), "Estado");
    
    const resultados = auditor.ejecutarTodo();
    
    // --- 4. ESCRITURA EN SHEETS (Polimorfismo) ---
    resultados.forEach(res => {
      const estrategiaResponsable = estrategias.find(e => e.name === res.name);
      
      if (estrategiaResponsable && res) {
        estrategiaResponsable.writeToSheet(res); 
      }
    });
    
    // --- 5. FINALIZACIÓN ---
    generarResumenSemaforo();
    ui.alert("✅ Auditoría de Google Drive completada con éxito.");

  } catch (error) {
    Logger.log("Error en auditoría de Google Drive: " + error.stack);
    ui.alert("❌ Error: " + error.message);
  }
}
