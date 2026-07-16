/**
 * ID Evaluado: ID-191
 * Configuración Evaluada: Operatividad de la Herramienta de Investigación de Seguridad
 * Filtro de Esquema / Búsqueda: Reports API (applicationName=admin) con nomenclaturas estrictas.
 */
class SecurityInvestigationToolUsageStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-191",
        valueKey: "valorPrincipal",
        noteKey: "comentario191",
        riskKey: "riesgo191",
        scoreKey: "score191"
      }
    ];

    super("Security Investigation Tool Usage Audit", configIDs);
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-191 (SECURITY INVESTIGATION TOOL) ==========");

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

    Logger.log(`[ID-191] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    if (!hasEnterpriseLicense) {
      Logger.log("[ID-191 - DIAGNÓSTICO] El inquilino carece de licencias Enterprise.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario191: "no posee licenciamiento de Google Workspace Enterprise en su censo de usuarios.",
        riesgo191: "Medio",
        score191: 2
      };
    }

    // =====================================================================
    // VECTOR 2: Inspeccionar huellas de uso en Reports API
    // =====================================================================
    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();
    let authHeader = null;

    try {
      authHeader = authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly"
      ]);
    } catch (e) {
      Logger.log(`[ID-191 - WARN] No se pudo obtener el token DWD: ${e.message}. Usando token interactivo.`);
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

    // CORRECCIÓN: Nombres exactos en MAYÚSCULAS requeridos por el manifiesto de la API de Google
    const investigationEvents = [
      "SECURITY_INVESTIGATION_QUERY",
      "SECURITY_INVESTIGATION_ACTION",
      "SECURITY_INVESTIGATION_ACTION_COMPLETION",
      "SECURITY_INVESTIGATION_ACTION_CANCELLATION"
    ];

    let toolUsageCount = 0;
    const toolDetails = [];

    investigationEvents.forEach(eventName => {
      const url = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin` +
                  `?eventName=${eventName}&startTime=${startTime}&maxResults=250`;
      
      try {
        Logger.log(`[ID-191] Buscando operatividad del evento: ${eventName}...`);
        const response = this.fetchWithBackoff(url, options);
        const code = response.getResponseCode();
        const text = response.getContentText();
        
        if (code === 200) {
          const json = JSON.parse(text);
          const items = json.items || [];
          
          Logger.log(`[ID-191 - API] Respondió con HTTP 200 para ${eventName}. Registros analizados: ${items.length}`);
          
          items.forEach(item => {
            const events = item.events || [];
            events.forEach(ev => {
              toolUsageCount++;
              
              const actorEmail = item.actor ? item.actor.email : "Desconocido";
              const eventTime = item.id ? item.id.time : "N/A";
              
              // Extraer la sintaxis de la consulta (SEARCH_QUERY)
              let querySyntax = "Consulta de investigación general";
              const parameters = ev.parameters || [];
              const searchParam = parameters.find(p => p.name === "SEARCH_QUERY" || p.name === "QUERY");
              
              if (searchParam && searchParam.value) {
                querySyntax = searchParam.value;
              }

              toolDetails.push(`[${ev.name}] por ${actorEmail} (Sintaxis: ${querySyntax.substring(0, 50)}${querySyntax.length > 50 ? '...' : ''})`);
            });
          });
        } else {
           Logger.log(`[ID-191 - WARN] HTTP ${code} al consultar ${eventName}. Detalle de Google: ${text}`);
        }
      } catch (err) {
        Logger.log(`[ID-191 - ERROR] Excepción al consultar ${eventName}: ${err.message}`);
      }
    });

    let valorPrincipal, comentario191, riesgo191;

    // RESPUESTA CORTA Y CONCISA
    if (toolUsageCount > 0) {
      valorPrincipal = "Habilitado";
      riesgo191 = "Bajo";
      
      const uniqueDetails = [...new Set(toolDetails)].slice(0, 10); 
      comentario191 = `Se detectaron ${toolUsageCount} consultas/acciones en la Herramienta de Investigación en los últimos 6 meses, evidenciando uso activo por parte del SOC.\nDetalle de eventos recientes:\n* ` + uniqueDetails.join("\n* ");
    } else {
      valorPrincipal = "Deshabilitado";
      riesgo191 = "Alto"; 
      comentario191 = `La licencia Enterprise faculta a la organización, pero se detectaron 0 eventos de investigación en los últimos 175 días. El procedimiento analítico y de triaje de amenazas mediante la Herramienta de Investigación es ineficaz u operativamente inexistente.`;
    }

    Logger.log(`[ID-191] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo191} | Eventos: ${toolUsageCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-191 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario191: comentario191,
      riesgo191: riesgo191,
      score191: this.calcularScoreDeRiesgo(riesgo191)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario191: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo191: "Medio",
      score191: 2
    };
  }
}