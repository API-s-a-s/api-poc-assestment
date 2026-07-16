/**
 * ID Evaluado: ID-190
 * Configuración Evaluada: Exportación automática de informes de Google Workspace a BigQuery (Validación Cruzada Workspace + GCP IAM)
 * Filtro de Esquema / Búsqueda: Reports API (activities.list) & GCP Resource Manager API (getIamPolicy)
 */
class WorkspaceReportsBigQueryExportCrossAuditStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-190",
        valueKey: "valorPrincipal",
        noteKey: "comentario190",
        riskKey: "riesgo190",
        scoreKey: "score190"
      }
    ];

    super("Workspace Reports BigQuery Export Audit (ID-190)", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Informes e investigación"; 
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  evaluateInMemory(globalContext) {
    const { census, auth } = globalContext;
    Logger.log("========== INICIO DIAGNÓSTICO ID-190 (BIGQUERY CROSS-VALIDATION) ==========");

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();

    // =====================================================================
    // VECTOR 1: Verificar licenciamiento (SKU Enterprise)
    // =====================================================================
    const ENTERPRISE_SKUS = [
      "/product/Google-Apps/sku/1010020020", // Enterprise Standard
      "/product/Google-Apps/sku/1010020025", // Enterprise Plus
      "/product/Google-Apps/sku/1010020030"  // Enterprise Starter
    ];

    const hasEnterpriseLicense = census.some(user => {
      const userLicenses = user.licenses || [];
      return userLicenses.some(sku => 
        ENTERPRISE_SKUS.includes(sku) || sku.toLowerCase().includes("enterprise")
      );
    });

    Logger.log(`[ID-190] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    if (!hasEnterpriseLicense) {
      Logger.log("[ID-190] Sin licencias Enterprise. Control no aplica.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario190: "El inquilino no posee licenciamiento de Google Workspace Enterprise en su censo de usuarios. La exportación nativa a BigQuery no está disponible en este nivel de suscripción.",
        riesgo190: "Medio",
        score190: 2
      };
    }

    // =====================================================================
    // VECTOR 2: Comprobación en Workspace Reports API
    // =====================================================================
    let reportsAuditHeader = null;
    try {
      reportsAuditHeader = authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly"
      ]);
    } catch (e) {
      Logger.log(`[ID-190 - WARN] No se pudo obtener DWD de Reports. Usando interactivo: ${e.message}`);
      reportsAuditHeader = authService.getAuthHeader();
    }

    const now = new Date();
    const safeSixMonthsAgo = new Date(now.getTime() - 175 * 24 * 60 * 60 * 1000);
    const startTime = safeSixMonthsAgo.toISOString();

    const optionsReports = {
      method: "get",
      headers: reportsAuditHeader,
      muteHttpExceptions: true
    };

    const eventName = "CHANGE_APPLICATION_SETTING";
    const reportsUrl = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin` +
                       `?eventName=${eventName}&startTime=${startTime}&maxResults=250`;

    let reportsSaysEnabled = false;

    try {
      Logger.log("[ID-190] Consultando API de Reports para buscar huellas de BigQuery...");
      const response = this.fetchWithBackoff(reportsUrl, optionsReports);
      const code = response.getResponseCode();
      const text = response.getContentText();

      Logger.log(`[ID-190 - REPORTS API] Código de respuesta HTTP: ${code}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const items = json.items || [];
        
        // AJUSTE DE LOGS: Reportamos cantidad de eventos y una vista previa súper recortada para evitar truncamientos
        Logger.log(`[ID-190 - REPORTS API] Se obtuvieron exitosamente ${items.length} eventos de auditoría.`);
        Logger.log(`[ID-190 - REPORTS API] Vista previa JSON (primeros 400 caracteres): ${text.substring(0, 400)}...`);
        
        items.forEach(item => {
          const events = item.events || [];
          events.forEach(ev => {
            let isBqRelated = false;
            let isNewValueTrue = false;

            const parameters = ev.parameters || [];
            parameters.forEach(param => {
              const paramName = (param.name || "").toUpperCase();
              const paramValue = (param.value || param.multiValue || "").toString().toUpperCase();
              
              if (paramName.includes("BIGQUERY") || paramValue.includes("BIGQUERY")) {
                isBqRelated = true;
              }
              if (paramName === "NEW_VALUE" && paramValue === "TRUE") {
                isNewValueTrue = true;
              }
            });

            if (isBqRelated && isNewValueTrue) {
              reportsSaysEnabled = true;
              Logger.log(`[ID-190] Evento de habilitación de BigQuery encontrado en Reports: ${ev.name}`);
            }
          });
        });
      }
    } catch (err) {
      Logger.log(`[ID-190 - ERROR] Error al consultar la API de Reports: ${err.message}`);
    }

    // =====================================================================
    // VECTOR 3: Validación Cruzada en GCP IAM (Resource Manager API)
    // =====================================================================
    let gcpSaysEnabled = false;
    let iamDetails = "";
    
    try {
      const gcpProjectId = authService.getGcpProjectId();
      Logger.log(`[ID-190] Realizando validación cruzada en el proyecto de GCP: ${gcpProjectId}`);
      
      const gcpToken = authService.getToken(); // Requiere scope cloud-platform
      const iamUrl = `https://cloudresourcemanager.googleapis.com/v1/projects/${gcpProjectId}:getIamPolicy`;
      
      const iamResponse = UrlFetchApp.fetch(iamUrl, {
        method: "post",
        contentType: "application/json",
        headers: { "Authorization": "Bearer " + gcpToken },
        muteHttpExceptions: true
      });

      const iamCode = iamResponse.getResponseCode();
      const iamText = iamResponse.getContentText();

      Logger.log(`[ID-190 - GCP IAM API] Código de respuesta HTTP: ${iamCode}`);
      // Ajustamos también este log por si la política IAM del proyecto es gigante
      Logger.log(`[ID-190 - GCP IAM API] Vista previa de política IAM (primeros 400 caracteres): ${iamText.substring(0, 400)}...`);

      if (iamCode === 200) {
        const iamJson = JSON.parse(iamText);
        const bindings = iamJson.bindings || [];
        
        const targetMember = "serviceAccount:gapps-reports@system.gserviceaccount.com";
        const requiredRoles = ["roles/bigquery.dataEditor", "roles/editor", "roles/owner", "roles/bigquery.admin"];

        bindings.forEach(binding => {
          if (requiredRoles.includes(binding.role)) {
            const members = binding.members || [];
            if (members.includes(targetMember)) {
              gcpSaysEnabled = true;
              iamDetails = `La cuenta de sistema '${targetMember}' tiene asignado el rol '${binding.role}'.`;
              Logger.log(`[ID-190] Confirmado en GCP IAM: ${iamDetails}`);
            }
          }
        });
      } else {
        Logger.log(`[ID-190 - WARN] HTTP ${iamCode} al leer política IAM de GCP. Detalle: ${iamText}`);
        iamDetails = `No se pudo verificar el permiso en GCP (HTTP ${iamCode}). Detalle: ${iamText}`;
      }
    } catch (e) {
      Logger.log(`[ID-190 - ERROR] Error en la validación cruzada de GCP: ${e.message}`);
      iamDetails = `Error al conectar con GCP Resource Manager: ${e.message}`;
    }

    // =====================================================================
    // EVALUACIÓN FINAL
    // =====================================================================
    let valorPrincipal, comentario190, riesgo190;

    if (gcpSaysEnabled || reportsSaysEnabled) {
      valorPrincipal = "Habilitado";
      riesgo190 = "Bajo";
      comentario190 = "La exportación de logs de Workspace a BigQuery está activa. " + 
                      (gcpSaysEnabled ? `Confirmado por GCP IAM: ${iamDetails}` : "Confirmado por registros históricos en la API de Reports.");
    } else {
      valorPrincipal = "Deshabilitado";
      riesgo190 = "Alto";
      comentario190 = "No se detectó la exportación de Workspace a BigQuery activa. " + 
                      "La cuenta de servicio del sistema no tiene permisos asignados en el proyecto de GCP o no hay registros de configuración recientes. " +
                      `Detalle GCP: ${iamDetails}`;
    }

    Logger.log(`[ID-190] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo190}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-190 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario190: comentario190,
      riesgo190: riesgo190,
      score190: this.calcularScoreDeRiesgo(riesgo190)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario190: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo190: "Medio",
      score190: 2
    };
  }
}