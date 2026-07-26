/**
 * ID Evaluado: ID-195
 * Configuración Evaluada: Reglas de informes de seguridad (Notificaciones)
 * Filtro de Esquema: Reports API (applicationName=rules) y Alert Center API (v1beta1)
 */
class SecurityReportingRulesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-195",
        valueKey: "valorPrincipal",
        noteKey: "comentario195",
        riskKey: "riesgo195",
        scoreKey: "score195"
      }
    ];

    super("Security Reporting Rules Audit", configIDs);
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
    Logger.log("========== INICIO DIAGNÓSTICO ID-195 (REPORTING RULES & NOTIFICATIONS) ==========");

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

    Logger.log(`[ID-195] ¿Posee licenciamiento Enterprise?: ${hasEnterpriseLicense}`);

    if (!hasEnterpriseLicense) {
      Logger.log("[ID-195 - DIAGNÓSTICO] El inquilino carece de licencias Enterprise.");
      return {
        name: this.name,
        valorPrincipal: "No aplica",
        comentario195: "El inquilino no posee licenciamiento de Google Workspace Enterprise. Las Reglas de Informes de Seguridad personalizadas no están habilitadas para este SKU.",
        riesgo195: "Medio",
        score195: 2
      };
    }

    // =====================================================================
    // VECTOR 2: Inventario de Reglas (Reports API) y Alertas (Alert Center)
    // =====================================================================
    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();
    let authHeader = null;

    try {
      // Nota: Utiliza los mismos scopes del ID-179. No requiere scopes DWD nuevos.
      authHeader = authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/apps.alerts"
      ]);
    } catch (e) {
      Logger.log(`[ID-195 - WARN] No se pudo obtener el token DWD: ${e.message}. Usando token interactivo.`);
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

    let rulesConfiguredCount = 0;
    const ruleDetails = [];
    
    // FASE 1: Buscar configuración de reglas en Reports API (espacio de nombres 'rules')
    const rulesEvents = ["CREATE_RULE", "UPDATE_RULE"];
    
    rulesEvents.forEach(eventName => {
      const rulesUrl = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/rules` +
                       `?eventName=${eventName}&startTime=${startTime}&maxResults=250`;
                       
      try {
        Logger.log(`[ID-195] Buscando configuración de reglas (${eventName})...`);
        const response = this.fetchWithBackoff(rulesUrl, options);
        const code = response.getResponseCode();
        
        if (code === 200) {
          const json = JSON.parse(response.getContentText());
          const items = json.items || [];
          
          Logger.log(`[ID-195 - API] Reports API respondió HTTP 200 para ${eventName}. Registros analizados: ${items.length}`);
          
          items.forEach(item => {
            const events = item.events || [];
            events.forEach(ev => {
              rulesConfiguredCount++;
              
              let ruleName = "Regla de seguridad";
              const parameters = ev.parameters || [];
              const nameParam = parameters.find(p => p.name === "RULE_NAME");
              if (nameParam && nameParam.value) ruleName = nameParam.value;

              ruleDetails.push(`[${ev.name}] - Regla: ${ruleName}`);
            });
          });
        } else {
          Logger.log(`[ID-195 - WARN] HTTP ${code} en Reports API para ${eventName}.`);
        }
      } catch (err) {
        Logger.log(`[ID-195 - ERROR] Excepción al consultar Reports API: ${err.message}`);
      }
    });

    // FASE 2: Validar generación de notificaciones en el Alert Center (v1beta1)
    let alertsTriggeredCount = 0;
    const alertsUrl = `https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=250`;
    
    try {
      Logger.log(`[ID-195] Verificando recepción de notificaciones en Alert Center...`);
      const response = this.fetchWithBackoff(alertsUrl, options);
      const code = response.getResponseCode();
      
      if (code === 200) {
        const json = JSON.parse(response.getContentText());
        const alerts = json.alerts || [];
        
        Logger.log(`[ID-195 - API] Alert Center respondió HTTP 200. Alertas analizadas: ${alerts.length}`);
        
        alerts.forEach(alert => {
          const type = alert.type || "";
          // Google mapea las Reporting Rules principalmente a estos tipos en el Alert Center
          if (type === "ActivityRule" || type === "RuleViolation" || type === "ReportingRule") {
            alertsTriggeredCount++;
          }
        });
      } else {
        Logger.log(`[ID-195 - WARN] HTTP ${code} en Alert Center API.`);
      }
    } catch (err) {
      Logger.log(`[ID-195 - ERROR] Excepción al consultar Alert Center API: ${err.message}`);
    }

    // =====================================================================
    // DIAGNÓSTICO FINAL Y CÁLCULO DE RIESGO
    // =====================================================================
    let valorPrincipal, comentario195, riesgo195;

    if (alertsTriggeredCount > 0 || rulesConfiguredCount > 0) {
      valorPrincipal = "Habilitado";
      riesgo195 = "Bajo";
      
      const uniqueDetails = [...new Set(ruleDetails)].slice(0, 5);
      comentario195 = `Se detectó configuración activa de reglas. ${alertsTriggeredCount} notificaciones emitidas en el Alert Center recientemente.`;
      
    } else {
      valorPrincipal = "Deshabilitado";
      riesgo195 = "Medio"; // Medio por la limitación de la ventana de tiempo de 6 meses
      comentario195 = `No se detectaron configuraciones de reglas de informes ni alertas disparadas en los últimos 175 días. Verifique manualmente en 'Seguridad > Centro de seguridad > Reglas'.`;
    }

    Logger.log(`[ID-195] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo195} | Alertas emitidas: ${alertsTriggeredCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-195 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario195: comentario195,
      riesgo195: riesgo195,
      score195: this.calcularScoreDeRiesgo(riesgo195)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario195: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo195: "Medio",
      score195: 2
    };
  }
}