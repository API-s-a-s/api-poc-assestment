/**
 * ID Evaluado: ID-179
 * Configuración Evaluada: Reglas de actividad de seguridad (Automatizar acciones)
 * Filtro de Esquema / Búsqueda: Reports API (applicationName=rules) y Alert Center API (v1beta1)
 */
class SecurityActivityRulesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-179",
        valueKey: "valorPrincipal",
        noteKey: "comentario179",
        riskKey: "riesgo179",
        scoreKey: "score179"
      }
    ];

    super("Security Activity Rules Audit", configIDs);
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-179 (SECURITY ACTIVITY RULES) ==========");

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

    Logger.log(`[ID-179] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    if (!hasEnterpriseLicense) {
      Logger.log("[ID-179 - DIAGNÓSTICO] El inquilino carece de licencias Enterprise.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario179: "El inquilino no posee licenciamiento de Google Workspace Enterprise. Las reglas de actividad (automatización) no están habilitadas para este SKU.",
        riesgo179: "Medio",
        score179: 2
      };
    }

    // =====================================================================
    // VECTOR 2: Inspeccionar eventos de Reglas y Centro de Alertas
    // =====================================================================
    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();
    let authHeader = null;

    try {
      authHeader = authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/apps.alerts"
      ]);
    } catch (e) {
      Logger.log(`[ID-179 - WARN] No se pudo obtener el token DWD: ${e.message}. Usando token interactivo.`);
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

    let rulesTriggeredCount = 0;
    const ruleNamesTriggered = new Set();
    
    // -----------------------------------------------------------------
    // SUB-VECTOR A: Reports API (applicationName = rules)
    // -----------------------------------------------------------------
    const rulesUrl = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/rules` +
                     `?startTime=${startTime}&maxResults=250`;
                     
    try {
      Logger.log(`[ID-179] Buscando telemetría de ejecución de reglas...`);
      const response = this.fetchWithBackoff(rulesUrl, options);
      const code = response.getResponseCode();
      
      if (code === 200) {
        const json = JSON.parse(response.getContentText());
        const items = json.items || [];
        
        Logger.log(`[ID-179 - API] Reports API (rules) respondió HTTP 200. Registros analizados: ${items.length}`);
        
        items.forEach(item => {
          const events = item.events || [];
          events.forEach(ev => {
            rulesTriggeredCount++;
            
            const parameters = ev.parameters || [];
            const ruleNameParam = parameters.find(p => p.name === "RULE_NAME");
            if (ruleNameParam && ruleNameParam.value) {
              ruleNamesTriggered.add(ruleNameParam.value);
            }
          });
        });
      } else {
        Logger.log(`[ID-179 - WARN] HTTP ${code} en Reports API (rules).`);
      }
    } catch (err) {
      Logger.log(`[ID-179 - ERROR] Excepción al consultar Reports API: ${err.message}`);
    }

    // -----------------------------------------------------------------
    // SUB-VECTOR B: Alert Center API (v1beta1 - Producción Oficial)
    // -----------------------------------------------------------------
    let totalRuleAlerts = 0;
    let notStartedAlerts = 0;
    
    // CORRECCIÓN: Usando v1beta1 que es el único endpoint real y funcional para Alert Center de Google
    const alertsUrl = `https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=250`;
    
    try {
      Logger.log(`[ID-179] Verificando estado del Centro de Alertas (Alert Center v1beta1)...`);
      const response = this.fetchWithBackoff(alertsUrl, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      if (code === 200) {
        const json = JSON.parse(text);
        const alerts = json.alerts || [];
        
        Logger.log(`[ID-179 - API] Alert Center respondió HTTP 200. Alertas analizadas: ${alerts.length}`);
        
        alerts.forEach(alert => {
          const type = alert.type || "";
          if (type === "ActivityRule" || type === "RuleViolation" || type === "SuspiciousActivity") {
            totalRuleAlerts++;
            
            const status = (alert.metadata && alert.metadata.status) ? alert.metadata.status : "NOT_STARTED";
            if (status === "NOT_STARTED") {
              notStartedAlerts++;
            }
          }
        });
      } else {
        Logger.log(`[ID-179 - WARN] HTTP ${code} en Alert Center API. Detalle: ${text}`);
      }
    } catch (err) {
      Logger.log(`[ID-179 - ERROR] Excepción al consultar Alert Center API: ${err.message}`);
    }

    // =====================================================================
    // DIAGNÓSTICO FINAL Y CÁLCULO DE RIESGO
    // =====================================================================
    let valorPrincipal, comentario179, riesgo179;

    if (rulesTriggeredCount > 0) {
      valorPrincipal = "Habilitado";
      
      // Lógica de Fatiga de Alertas (Alert Fatigue)
      if (totalRuleAlerts > 10 && (notStartedAlerts / totalRuleAlerts) > 0.7) {
        riesgo179 = "Medio"; // Castigamos el riesgo por fatiga de alertas
        comentario179 = `Se detectaron ${rulesTriggeredCount} ejecuciones de reglas de seguridad, pero se identificó Fatiga de Alertas. El ${Math.round((notStartedAlerts/totalRuleAlerts)*100)}% de alertas están en estado NOT_STARTED. Reglas activadas: ${Array.from(ruleNamesTriggered).slice(0, 5).join(", ")}`;
      } else {
        riesgo179 = "Bajo";
        comentario179 = `Se detectaron ${rulesTriggeredCount} ejecuciones de reglas de seguridad en los últimos 6 meses, con un volumen de atención manejable por parte de los administradores.\n` +
                        `Reglas activadas: ${Array.from(ruleNamesTriggered).slice(0, 5).join(", ")}`;
      }
      
    } else {
      valorPrincipal = "Deshabilitado";
      riesgo179 = "Medio"; 
      comentario179 = `No se detectaron disparos (triggers) de reglas de actividad en los últimos 175 días. Verifique manualmente en 'Seguridad > Centro de alertas > Reglas'.`;
    }

    Logger.log(`[ID-179] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo179} | Reglas ejecutadas: ${rulesTriggeredCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-179 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario179: comentario179,
      riesgo179: riesgo179,
      score179: this.calcularScoreDeRiesgo(riesgo179)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario179: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo179: "Medio",
      score179: 2
    };
  }
}