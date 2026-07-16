/**
 * ID Evaluado: ID-176
 * Configuración Evaluada: Transmitir registros de Gmail a BigQuery para análisis y preservación
 * Filtro de Esquema / Búsqueda: Reports API (applicationName=admin, events=APPLICATION_SETTINGS)
 */
class BigQueryLogExportStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-176",
        valueKey: "valorPrincipal",
        noteKey: "comentario176",
        riskKey: "riesgo176",
        scoreKey: "score176"
      }
    ];

    super("BigQuery Log Export Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Preparar y supervisar"; 
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-176 (BIGQUERY EXPORT) ==========");

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

    Logger.log(`[ID-176] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    if (!hasEnterpriseLicense) {
      Logger.log("[ID-176 - DIAGNÓSTICO] El inquilino carece de licencias Enterprise. Exportación no soportada nativamente.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario176: "El inquilino no posee licenciamiento de Google Workspace Enterprise en su censo de usuarios. La funcionalidad de exportación nativa de logs a Google BigQuery no está disponible para este nivel de licenciamiento, por lo que este control no aplica.",
        riesgo176: "Medio",
        score176: 2
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
      Logger.log(`[ID-176 - WARN] No se pudo obtener el token DWD: ${e.message}. Usando token interactivo.`);
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

    // CORRECCIÓN: Se eliminó UPDATE_APPLICATION_SETTING para evitar el HTTP 400
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
        Logger.log(`[ID-176] Buscando evento administrativo: ${eventName}...`);
        const response = this.fetchWithBackoff(url, options);
        const code = response.getResponseCode();
        const text = response.getContentText();
        
        if (code === 200) {
          const json = JSON.parse(text);
          const items = json.items || [];
          
          items.forEach(item => {
            const events = item.events || [];
            events.forEach(ev => {
              let isBqRelated = false;
              
              const parameters = ev.parameters || [];
              parameters.forEach(param => {
                const paramName = (param.name || "").toUpperCase();
                const paramValue = (param.value || param.multiValue || "").toString().toUpperCase();
                
                // Búsqueda robusta de parámetros relacionados a BQ
                if (paramName.includes("BIGQUERY") || paramValue.includes("BIGQUERY") || paramValue.includes("BIG_QUERY")) {
                  isBqRelated = true;
                }
              });

              if (isBqRelated) {
                bqEventsCount++;
                const actorEmail = item.actor ? item.actor.email : "Desconocido";
                const eventTime = item.id ? item.id.time : "N/A";
                bqDetails.push(`[${ev.name}] configurado por ${actorEmail} en ${eventTime}`);
              }
            });
          });
        } else {
           Logger.log(`[ID-176 - WARN] HTTP ${code} al consultar ${eventName}. Detalle de Google: ${text}`);
        }
      } catch (err) {
        Logger.log(`[ID-176 - ERROR] Excepción al consultar ${eventName}: ${err.message}`);
      }
    });

    let valorPrincipal, comentario176, riesgo176;

    if (bqEventsCount > 0) {
      valorPrincipal = "Habilitado";
      riesgo176 = "Bajo";
      
      const uniqueDetails = [...new Set(bqDetails)];
      comentario176 = `Se detectaron ${bqEventsCount} configuración de exportación de BigQuery en los últimos 6 meses.\n` +
                      `etalle de eventos detectados:` + `uniqueDetails.join("\n* ")`;
    } else {
      // Como no podemos saber si se configuró hace 2 años o nunca, el valor debe reflejar esa incertidumbre o fallar seguro
      valorPrincipal = "Deshabilitado";
      riesgo176 = "Medio"; // Lo bajamos a medio porque puede ser un falso negativo por tiempo
      comentario176 = `No se detectaron rastros de configuración de BigQuery Export en los últimos 175 días, verifique manualmente en 'Menú > Informes > Exportación a BigQuery' en la consola de Google Workspace.`;
    }

    Logger.log(`[ID-176] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo176} | Eventos: ${bqEventsCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-176 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario176: comentario176,
      riesgo176: riesgo176,
      score176: this.calcularScoreDeRiesgo(riesgo176)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario176: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo176: "Medio",
      score176: 2
    };
  }
}