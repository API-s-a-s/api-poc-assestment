/**
 * ID Evaluado: ID-177
 * Configuración Evaluada: Exportar automáticamente informes de Google Workspace a BigQuery para análisis y preservación
 * Filtro de Esquema / Búsqueda: Reports API (applicationName=admin, events=APPLICATION_SETTINGS)
 */
class WorkspaceReportsBigQueryExportStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-177",
        valueKey: "valorPrincipal",
        noteKey: "comentario177",
        riskKey: "riesgo177",
        scoreKey: "score177"
      }
    ];

    super("Workspace Reports BigQuery Export Audit", configIDs);
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

  evaluateInMemory(globalContext) {
    const { census, auth } = globalContext;
    Logger.log("========== INICIO DIAGNÓSTICO ID-177 (WORKSPACE REPORTS TO BIGQUERY) ==========");

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    // =====================================================================
    // VECTOR 1: Verificar licenciamiento (SKU Enterprise) desde el Censo
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

    Logger.log(`[ID-177] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    if (!hasEnterpriseLicense) {
      Logger.log("[ID-177 - DIAGNÓSTICO] El inquilino carece de licencias Enterprise.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario177: "El inquilino no posee licenciamiento de Google Workspace Enterprise en su censo de usuarios.",
        riesgo177: "Medio",
        score177: 2
      };
    }

    // =====================================================================
    // VECTOR 2: Inspeccionar huellas de configuración en Reports API
    // =====================================================================
    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();
    let authHeader = null;

    try {
      authHeader = authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly"
      ]);
    } catch (e) {
      Logger.log(`[ID-177 - WARN] No se pudo obtener el token DWD: ${e.message}. Usando token interactivo.`);
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

    const settingsEvents = [
      "CREATE_APPLICATION_SETTING",
      "CHANGE_APPLICATION_SETTING",
      "DELETE_APPLICATION_SETTING"
    ];

    let bqEventsCount = 0;
    const bqDetails = [];

    settingsEvents.forEach(eventName => {
      const url = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin` +
                  `?eventName=${eventName}&startTime=${startTime}&maxResults=250`;
      
      try {
        Logger.log(`[ID-177] Buscando huella de evento administrativo: ${eventName}...`);
        const response = this.fetchWithBackoff(url, options);
        const code = response.getResponseCode();
        const text = response.getContentText();
        
        if (code === 200) {
          const json = JSON.parse(text);
          const items = json.items || [];
          
          // NUEVO LOG PARA VISIBILIDAD DE ÉXITO:
          Logger.log(`[ID-177 - API] Respondió con HTTP 200 para ${eventName}. Registros analizados: ${items.length}`);
          
          items.forEach(item => {
            const events = item.events || [];
            events.forEach(ev => {
              let isBqRelated = false;
              
              const parameters = ev.parameters || [];
              parameters.forEach(param => {
                const paramName = (param.name || "").toUpperCase();
                const paramValue = (param.value || param.multiValue || "").toString().toUpperCase();
                
                if (paramName.includes("BIGQUERY") || paramValue.includes("BIGQUERY") || paramValue.includes("BIG_QUERY")) {
                  isBqRelated = true;
                }
              });

              if (isBqRelated) {
                bqEventsCount++;
                const actorEmail = item.actor ? item.actor.email : "Desconocido";
                const eventTime = item.id ? item.id.time : "N/A";
                bqDetails.push(`[${ev.name}] por ${actorEmail} en ${eventTime}`);
              }
            });
          });
        } else {
           Logger.log(`[ID-177 - WARN] HTTP ${code} al consultar ${eventName}. Detalle de Google: ${text}`);
        }
      } catch (err) {
        Logger.log(`[ID-177 - ERROR] Excepción al consultar ${eventName}: ${err.message}`);
      }
    });

    let valorPrincipal, comentario177, riesgo177;

    // RESPUESTA CORTA Y CONCISA SEGÚN TUS REQUERIMIENTOS:
    if (bqEventsCount > 0) {
      valorPrincipal = "Habilitado";
      riesgo177 = "Bajo";
      
      const uniqueDetails = [...new Set(bqDetails)];
      comentario177 = `Se detectaron ${bqEventsCount} configuraciones de exportación de BigQuery en los últimos 6 meses.\nDetalle de eventos detectados:\n* ` + uniqueDetails.join("\n* ");
    } else {
      valorPrincipal = "Deshabilitado";
      riesgo177 = "Medio"; 
      comentario177 = `No se detectaron rastros de configuración de BigQuery Export en los últimos 175 días, verifique manualmente en 'Menú > Informes > Exportación a BigQuery' en la consola de Google Workspace.`;
    }

    Logger.log(`[ID-177] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo177} | Eventos: ${bqEventsCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-177 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario177: comentario177,
      riesgo177: riesgo177,
      score177: this.calcularScoreDeRiesgo(riesgo177)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario177: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo177: "Medio",
      score177: 2
    };
  }
}