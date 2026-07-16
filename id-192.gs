/**
 * ID Evaluado: ID-192
 * Configuración Evaluada: Requerir un revisor en acciones donde más de 300 elementos se vean afectados
 * Filtro de Esquema: Reports API (CHANGE_APPLICATION_SETTING y SECURITY_INVESTIGATION_ACTION_VERIFICATION_REQUEST)
 */
class RequireReviewerBulkActionsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-192",
        valueKey: "valorPrincipal",
        noteKey: "comentario192",
        riskKey: "riesgo192",
        scoreKey: "score192"
      }
    ];

    super("Require Reviewer Bulk Actions Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Informes e investigación"; 
  }

  /**
   * Mapeo de puntajes estándar de riesgo.
   */
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-192 (REQUIRE REVIEWER FOR BULK ACTIONS) ==========");

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

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

    Logger.log(`[ID-192] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    if (!hasEnterpriseLicense) {
      Logger.log("[ID-192 - DIAGNÓSTICO] El inquilino carece de licencias Enterprise.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario192: "El inquilino no posee licenciamiento Enterprise. La configuración para requerir revisores en acciones masivas no está habilitada para este SKU.",
        riesgo192: "Medio",
        score192: 2
      };
    }

    // =====================================================================
    // VECTOR 2: Inspeccionar Configuración y Flujo de Trabajo en Reports API
    // =====================================================================
    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();
    let authHeader = null;

    try {
      authHeader = authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly"
      ]);
    } catch (e) {
      Logger.log(`[ID-192 - WARN] No se pudo obtener token DWD: ${e.message}. Usando interactivo.`);
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

    // Eventos a auditar: Configuración general y Flujo de aprobación asíncrono
    const eventsToAudit = [
      "CHANGE_APPLICATION_SETTING", 
      "SECURITY_INVESTIGATION_ACTION_VERIFICATION_REQUEST" 
    ];

    let isConfiguredRecently = false;
    let workflowEventsCount = 0;
    const workflowDetails = [];

    eventsToAudit.forEach(eventName => {
      const url = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin` +
                  `?eventName=${eventName}&startTime=${startTime}&maxResults=250`;
      
      try {
        Logger.log(`[ID-192] Buscando huella del evento: ${eventName}...`);
        const response = this.fetchWithBackoff(url, options);
        const code = response.getResponseCode();
        const text = response.getContentText();
        
        if (code === 200) {
          const json = JSON.parse(text);
          const items = json.items || [];
          
          Logger.log(`[ID-192 - API] Respondió con HTTP 200 para ${eventName}. Registros analizados: ${items.length}`);
          
          items.forEach(item => {
            const events = item.events || [];
            events.forEach(ev => {
              
              // A: Si es un cambio de configuración, buscamos explícitamente "REVIEWER"
              if (ev.name === "CHANGE_APPLICATION_SETTING") {
                const parameters = ev.parameters || [];
                parameters.forEach(param => {
                  const paramName = (param.name || "").toUpperCase();
                  if (paramName.includes("REVIEWER") || paramName.includes("REQUIRE_REVIEWER")) {
                    isConfiguredRecently = true;
                  }
                });
              } 
              // B: Si es una solicitud de verificación (flujo de trabajo operativo)
              else if (ev.name === "SECURITY_INVESTIGATION_ACTION_VERIFICATION_REQUEST") {
                workflowEventsCount++;
                const actorEmail = item.actor ? item.actor.email : "Desconocido";
                workflowDetails.push(`Solicitud de revisión generada por ${actorEmail} en ${item.id ? item.id.time : "N/A"}`);
              }
            });
          });
        } else {
           Logger.log(`[ID-192 - WARN] HTTP ${code} al consultar ${eventName}. Detalle: ${text}`);
        }
      } catch (err) {
        Logger.log(`[ID-192 - ERROR] Excepción al consultar ${eventName}: ${err.message}`);
      }
    });

    let valorPrincipal, comentario192, riesgo192;

    // DIAGNÓSTICO: Si hay uso del workflow, automáticamente sabemos que está configurado
    if (workflowEventsCount > 0) {
      valorPrincipal = "Habilitado";
      riesgo192 = "Bajo";
      
      const uniqueDetails = [...new Set(workflowDetails)].slice(0, 5); 
      comentario192 = `Se detectaron ${workflowEventsCount} solicitudes de revisión de acciones masivas en los últimos 6 meses.\nDetalle reciente:\n* ` + uniqueDetails.join("\n* ");
      
    } else if (isConfiguredRecently) {
      // Se configuró en los últimos 175 días, pero no se ha ejecutado ninguna acción masiva (>300) aún
      valorPrincipal = "Sí";
      riesgo192 = "Medio"; 
      comentario192 = `Se detectó la habilitación afirmativa del control (Require Reviewer) en los últimos 175 días, pero no se registraron flujos de aprobación (0 solicitudes).`;
      
    } else {
      // No hay rastros de configuración reciente ni de uso operativo
      valorPrincipal = "No";
      riesgo192 = "Medio"; // Asignamos medio por el posible falso negativo (limitación de tiempo)
      comentario192 = `No se detectaron solicitudes de revisión ni rastros de configuración en los últimos 175 días., se recomienda verificar manualmente en 'Seguridad > Centro de seguridad > Herramienta de investigación > Configuración'. Si está desactivado, el dominio corre un alto riesgo.`;
    }

    Logger.log(`[ID-192] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo192} | Flujos operativos: ${workflowEventsCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-192 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario192: comentario192,
      riesgo192: riesgo192,
      score192: this.calcularScoreDeRiesgo(riesgo192)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario192: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo192: "Medio",
      score192: 2
    };
  }
}