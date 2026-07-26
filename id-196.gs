/**
 * ID Evaluado: ID-196
 * Configuración Evaluada: Automatización de Acciones con Reglas de Actividad de Seguridad (SOAR)
 * Filtro de Esquema: Reports API (applicationName=rules y applicationName=admin)
 */
class SecurityActivityRulesAutomationStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-196",
        valueKey: "valorPrincipal",
        noteKey: "comentario196",
        riskKey: "riesgo196",
        scoreKey: "score196"
      }
    ];

    super("Security Activity Automation Audit", configIDs);
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-196 (SECURITY AUTOMATION - SOAR) ==========");

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

    Logger.log(`[ID-196] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    if (!hasEnterpriseLicense) {
      Logger.log("[ID-196 - DIAGNÓSTICO] El inquilino carece de licencias Enterprise.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario196: "El inquilino no posee licenciamiento Enterprise. Las reglas de automatización de actividad no están habilitadas para este SKU.",
        riesgo196: "Medio",
        score196: 2
      };
    }

    // =====================================================================
    // VECTOR 2: Inspeccionar Automatización en Reports API
    // =====================================================================
    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();
    let authHeader = null;

    try {
      authHeader = authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly"
      ]);
    } catch (e) {
      Logger.log(`[ID-196 - WARN] No se pudo obtener token DWD: ${e.message}. Usando interactivo.`);
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

    let automatedActionsCount = 0;
    const actionDetails = [];

    // FASE A: Auditar ejecuciones automatizadas generales desde 'rules'
    const rulesUrl = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/rules` +
                     `?startTime=${startTime}&maxResults=250`;
    
    try {
      Logger.log(`[ID-196] Buscando registros del motor de reglas (SOAR)...`);
      const response = this.fetchWithBackoff(rulesUrl, options);
      const code = response.getResponseCode();
      
      if (code === 200) {
        const json = JSON.parse(response.getContentText());
        const items = json.items || [];
        Logger.log(`[ID-196 - API] Respondió con HTTP 200 para applicationName=rules. Registros analizados: ${items.length}`);
        
        items.forEach(item => {
          // Buscamos acciones automatizadas por el sistema (actor system)
          const actorEmail = item.actor ? item.actor.email.toLowerCase() : "system";
          
          if (actorEmail === "system" || actorEmail.includes("system.gserviceaccount")) {
            const events = item.events || [];
            events.forEach(ev => {
              const parameters = ev.parameters || [];
              let isPunitiveAction = false;
              let ruleName = "Regla desconocida";
              
              parameters.forEach(p => {
                if (p.name === "RULE_NAME") ruleName = p.value;
                if (p.name === "ACTION_NAME" || p.name === "ACTION") {
                  isPunitiveAction = true;
                }
              });

              if (isPunitiveAction) {
                automatedActionsCount++;
                actionDetails.push(`Acción del Sistema (Regla: ${ruleName})`);
              }
            });
          }
        });
      } else {
        Logger.log(`[ID-196 - WARN] HTTP ${code} en applicationName=rules. Detalle: ${response.getContentText()}`);
      }
    } catch (err) {
      Logger.log(`[ID-196 - ERROR] Excepción al consultar rules API: ${err.message}`);
    }

    // FASE B: Auditar suspensiones específicas en 'admin' originadas por el sistema
    // Nos ahorramos el 400 usando un evento de administrador estándar
    const adminUrl = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin` +
                     `?eventName=SUSPEND_USER&startTime=${startTime}&maxResults=250`;
    
    try {
      Logger.log(`[ID-196] Buscando suspensiones de usuarios automatizadas...`);
      const response = this.fetchWithBackoff(adminUrl, options);
      const code = response.getResponseCode();
      
      if (code === 200) {
        const json = JSON.parse(response.getContentText());
        const items = json.items || [];
        Logger.log(`[ID-196 - API] Respondió con HTTP 200 para SUSPEND_USER. Registros analizados: ${items.length}`);
        
        items.forEach(item => {
          const actorEmail = item.actor ? item.actor.email.toLowerCase() : "system";
          // Si el que suspende al usuario es el sistema o una regla, cuenta como SOAR
          if (actorEmail === "system" || actorEmail === "" || actorEmail.includes("rule")) {
            automatedActionsCount++;
            actionDetails.push(`Suspensión automatizada de usuario por el sistema`);
          }
        });
      } else {
        Logger.log(`[ID-196 - WARN] HTTP ${code} en applicationName=admin (SUSPEND_USER).`);
      }
    } catch (err) {
      Logger.log(`[ID-196 - ERROR] Excepción al consultar admin API: ${err.message}`);
    }

    let valorPrincipal, comentario196, riesgo196;

    if (automatedActionsCount > 0) {
      valorPrincipal = "Habilitado";
      riesgo196 = "Bajo";
      
      const uniqueDetails = [...new Set(actionDetails)].slice(0, 5);
      comentario196 = `Se detectaron ${automatedActionsCount} acciones automatizadas SOAR ejecutadas por el sistema en los últimos 6 meses.`;
      
    } else {
      valorPrincipal = "Deshabilitado";
      riesgo196 = "Medio"; 
      comentario196 = `No se detectaron acciones como SUSPEND_USER por el sistema en los últimos 175 días. Verifique manualmente si las reglas de actividad están configuradas.`;
    }

    Logger.log(`[ID-196] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo196} | Acciones automatizadas: ${automatedActionsCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-196 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario196: comentario196,
      riesgo196: riesgo196,
      score196: this.calcularScoreDeRiesgo(riesgo196)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario196: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo196: "Medio",
      score196: 2
    };
  }
}