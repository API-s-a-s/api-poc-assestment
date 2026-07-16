/**
 * ID Evaluado: ID-174
 * Configuración Evaluada: ¿Usa el panel de Control de seguridad? (SKU Enterprise)
 * Filtro de Esquema / Búsqueda: Reports API (Admin application log events)
 */
class SecurityCenterUsageStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-174",
        valueKey: "valorPrincipal",
        noteKey: "comentario174",
        riskKey: "riesgo174",
        scoreKey: "score174"
      }
    ];

    super("Security Center Usage Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Preparar y supervisar";
  }

  /**
   * Mapeo de puntajes estándar de riesgo según la fórmula matemática de auditoría.
   */
  calcularScoreDeRiesgo(nivelRiesgo) { 
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  /**
   * Ejecuta la validación en memoria y por API.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const { census, auth } = globalContext;

    Logger.log("========== INICIO DIAGNÓSTICO ID-174 (SECURITY CENTER USAGE) ==========");

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    // =====================================================================
    // VECTOR 1: Verificar licenciamiento (SKU Enterprise) desde el Censo
    // =====================================================================
    const ENTERPRISE_SKUS = [
      "/product/Google-Apps/sku/1010020020", // Google Workspace Enterprise Standard
      "/product/Google-Apps/sku/1010020025", // Google Workspace Enterprise Plus
      "/product/Google-Apps/sku/1010020030"  // Google Workspace Enterprise Starter
    ];

    const hasEnterpriseLicense = census.some(user => {
      const userLicenses = user.licenses || [];
      return userLicenses.some(sku => 
        ENTERPRISE_SKUS.includes(sku) || sku.toLowerCase().includes("enterprise")
      );
    });

    Logger.log(`[ID-174] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    // AJUSTE: Si no hay SKU Enterprise, no aplica y el riesgo es Medio
    if (!hasEnterpriseLicense) {
      Logger.log("[ID-174 - DIAGNÓSTICO] El inquilino carece de licencias Enterprise. Herramienta no habilitada.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario174: "El inquilino no posee licenciamiento de Google Workspace Enterprise (Standard, Plus o Starter) en su censo de usuarios. Por ende, las funciones del panel de control de seguridad no están habilitadas y la métrica no aplica.",
        riesgo174: "Medio",
        score174: 2
      };
    }

    // =====================================================================
    // VECTOR 2: Verificar interacción con la Reports API (últimos 175 días)
    // =====================================================================
    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();
    let authHeader = null;

    try {
      authHeader = authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly"
      ]);
    } catch (e) {
      Logger.log(`[ID-174 - WARN] No se pudo obtener el token DWD: ${e.message}. Usando token interactivo.`);
      authHeader = authService.getAuthHeader();
    }

    const now = new Date();
    const safeSixMonthsAgo = new Date(now.getTime() - 175 * 24 * 60 * 60 * 1000);
    const startTime = safeSixMonthsAgo.toISOString();

    const options = {
      method: "get",
      headers: authHeader,
      muteHttpExceptions: true
    };

    // Eventos esperados de la herramienta de investigación
    const securityInvestigationEvents = [
      "securityInvestigationQuery", "securityInvestigationAction", "securityInvestigationContentAccess",
      "securityInvestigationChartCreate", "securityInvestigationDownloadAttachment",
      "securityInvestigationObjectCreateDraftInvestigation", "securityInvestigationObjectDeleteInvestigation",
      "securityInvestigationObjectSaveInvestigation", "securityInvestigationActionCancellation",
      "securityInvestigationActionCompletion", "securityInvestigationActionRetry",
      "securityInvestigationActionVerificationRequest"
    ];

    // Eventos de extracción de datos sensibles
    const sensitiveDataActionEvents = [
      "SENSITIVE_AUDIT_EVENTS_ACCESSED", "SENSITIVE_AUDIT_EVENTS_HIDDEN", "SENSITIVE_AUDIT_EVENTS_UNHIDDEN"
    ];

    let matchedEventsCount = 0;
    const adminEventsSummary = {};
    const dataActionEventsSummary = {};

    // -----------------------------------------------------------------
    // SUB-VECTOR A: Extracción masiva de la aplicación 'admin'
    // -----------------------------------------------------------------
    const adminUrl = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin` +
                     `?startTime=${startTime}&maxResults=250`;
    try {
      const response = this.fetchWithBackoff(adminUrl, options);
      if (response.getResponseCode() === 200) {
        const json = JSON.parse(response.getContentText());
        (json.items || []).forEach(item => {
          (item.events || []).forEach(ev => {
            adminEventsSummary[ev.name] = (adminEventsSummary[ev.name] || 0) + 1;
            if (securityInvestigationEvents.indexOf(ev.name) !== -1) matchedEventsCount++;
          });
        });
      }
    } catch (err) {
      Logger.log(`[ID-174] Error admin: ${err.message}`);
    }

    // -----------------------------------------------------------------
    // SUB-VECTOR B: Extracción masiva de la aplicación 'admin_data_action'
    // -----------------------------------------------------------------
    const dataActionUrl = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin_data_action` +
                          `?startTime=${startTime}&maxResults=250`;
    try {
      const response = this.fetchWithBackoff(dataActionUrl, options);
      if (response.getResponseCode() === 200) {
        const json = JSON.parse(response.getContentText());
        (json.items || []).forEach(item => {
          (item.events || []).forEach(ev => {
            dataActionEventsSummary[ev.name] = (dataActionEventsSummary[ev.name] || 0) + 1;
            if (sensitiveDataActionEvents.indexOf(ev.name) !== -1) matchedEventsCount++;
          });
        });
      }
    } catch (err) {
      Logger.log(`[ID-174] Error admin_data_action: ${err.message}`);
    }

    // =====================================================================
    // DIAGNÓSTICO DE REGISTROS Y ANÁLISIS DE UMBRALES DE RIESGO
    // =====================================================================
    let valorPrincipal, comentario174, riesgo174;
    const tsFormat = Utilities.formatDate(now, Session.getScriptTimeZone(), "dd MMM yyyy, h:mm:ss a");
    
    // Preparar el texto de los logs para inyectarlo en el comentario final
    const logsInfo = `\n\n${tsFormat} Información [Frecuencia de Eventos 'admin' detectados]: ${JSON.stringify(adminEventsSummary)} \n` + 
                     `${tsFormat} Información [Frecuencia de Eventos 'admin_data_action' detectados]: ${JSON.stringify(dataActionEventsSummary)}`;

    // AJUSTE: Análisis de umbrales para el nivel de riesgo
    if (matchedEventsCount === 0) {
      // Cero registros: Peligro por inactividad
      valorPrincipal = "Deshabilitado";
      riesgo174 = "Alto";
      comentario174 = `Se registraron 0 eventos de interacción en la herramienta de investigación en los últimos 6 meses. Esto es de alto riesgo: significa que la organización padece de ceguera forense, está incurriendo en un gasto subutilizado y carece de procesos operativos de caza proactiva de amenazas (threat hunting) para investigar alertas del dominio.` + logsInfo;
      
    } else if (matchedEventsCount > 1000) {
      // Registros masivos: Peligro por anomalía (Ej. 5000+ registros)
      valorPrincipal = "Habilitado";
      riesgo174 = "Medio"; // Opcionalmente podrías pasarlo a "Alto" si lo prefieres
      comentario174 = `Se registraron ${matchedEventsCount} eventos en los últimos 6 meses. Un volumen tan excesivamente alto es una anomalía de seguridad; podría indicar un incidente grave y prolongado que está siendo mitigado, o bien, la presencia de un script automatizado extrayendo datos sensibles de auditoría. Se recomienda revisar el origen de estas peticiones masivas.` + logsInfo;
      
    } else {
      // Uso sano y proporcional (1 a 1000 registros)
      valorPrincipal = "Habilitado";
      riesgo174 = "Bajo";
      comentario174 = `Se registraron ${matchedEventsCount} eventos de interacción en los últimos 6 meses. Esto evidencia un uso sano, activo y proporcionado de la herramienta para la auditoría forense y la caza de amenazas en el dominio.` + logsInfo;
    }

    Logger.log(`[ID-174] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo174} | Eventos: ${matchedEventsCount}`);

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario174: comentario174,
      riesgo174: riesgo174,
      score174: this.calcularScoreDeRiesgo(riesgo174)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario174: `Ocurrió un error inesperado al procesar la API de Reportes: ${msg}`,
      riesgo174: "Medio",
      score174: 2
    };
  }
}