/**
 * Estrategia para auditar las reglas de enrutamiento de correo.
 * ID-090: Reglas de enrutamiento adicionales.
 */
class GmailRoutingRulesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-090", 
        valueKey: "valorPrincipal",
        noteKey: "comentario090",
        riskKey: "riesgo090",
        scoreKey: "score090"
      }
    ];
    super("Gmail Routing Rules Audit", configIDs);
    this.category = "Email y DNS";
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  checkAdminReportsForSetting(settingName) {
    try {
      const sixMonthsAgo = new Date();
      sixMonthsAgo.setDate(sixMonthsAgo.getDate() - 180);
      Logger.log(`[DEBUG ID-090] Iniciando checkAdminReportsForSetting para: ${settingName}. Buscando desde: ${sixMonthsAgo.toISOString()}`);
      
      const response = AdminReports.Activities.list("all", "admin", {
        eventName: "CHANGE_GMAIL_SETTING",
        startTime: sixMonthsAgo.toISOString(),
        maxResults: 50
      });
      
      Logger.log(`[DEBUG ID-090] Respuesta de AdminReports obtenida. Items: ${response.items ? response.items.length : 0}`);
      
      if (response.items && response.items.length > 0) {
        for (const item of response.items) {
          for (const event of item.events) {
            if (event.name === "CHANGE_GMAIL_SETTING") {
              const paramName = event.parameters.find(p => p.name === "SETTING_NAME");
              const paramEnabled = event.parameters.find(p => p.name === "SETTING_ENABLED");
              const paramNewValue = event.parameters.find(p => p.name === "NEW_VALUE");
              
              if (paramName && paramName.value && paramName.value.toLowerCase().includes(settingName.toLowerCase())) {
                Logger.log(`[DEBUG ID-090] Coincidencia encontrada en AdminReports. Parámetros: SETTING_NAME=${paramName.value}, ENABLED=${paramEnabled ? paramEnabled.boolValue : 'N/A'}, NEW_VALUE=${paramNewValue ? paramNewValue.value : 'N/A'}`);
                return {
                  found: true,
                  enabled: paramEnabled ? paramEnabled.boolValue : null,
                  newValue: paramNewValue ? paramNewValue.value : null,
                  raw: item
                };
              }
            }
          }
        }
      }
      Logger.log(`[DEBUG ID-090] No se encontraron configuraciones en AdminReports para: ${settingName}`);
      return { found: false };
    } catch (e) {
      Logger.log(`[WARN] Reports API fallback failed: ${e.message}`);
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    Logger.log(`[DEBUG ID-090] Iniciando evaluateInMemory. Total políticas recibidas: ${policies.length}`);
    const routingPolicies = policies.filter(p => p.setting && ((p.setting.type || "").includes("routing")));
    Logger.log(`[DEBUG ID-090] Políticas de Gmail Routing Rules filtradas: ${routingPolicies.length}`);

    let rulesCount = 0;
    let dataSource = "Memory";
    let rawData = null;

    if (routingPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(routingPolicies, routingPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-090] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-090] valueNode: ${JSON.stringify(valueNode)}`);
        const rules = valueNode.rules || valueNode.settingRules || valueNode.routingRules || [];
        Logger.log(`[DEBUG ID-090] Reglas de enrutamiento detectadas: ${rules.length}`);
        rulesCount = rules.length;
      }
    } else {
      Logger.log(`[LOG] Routing rules no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Routing");
      if (logResult.found) {
        rulesCount = (logResult.enabled === true || (logResult.newValue && logResult.newValue !== "")) ? 1 : 0;
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        rulesCount = 0;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let riesgo090, comentario090;

    if (rulesCount > 0) {
      riesgo090 = "Medio"; // Medio porque el enrutamiento malicioso (ej. dual delivery oculto) es un vector clásico de exfiltración.
      comentario090 = `Se detectaron ${rulesCount} reglas de enrutamiento adicionales.`;
    } else {
      riesgo090 = "Bajo";
      comentario090 = `No se detectaron reglas de enrutamiento adicionales.`;
    }

    Logger.log(`[LOG] Routing Rules Audit: ${rulesCount} reglas detectadas. | Riesgo: ${riesgo090} | Fuente: ${dataSource}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: rulesCount,
      comentario090: comentario090,
      riesgo090: riesgo090,
      score090: this.calcularScoreDeRiesgo(riesgo090)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo090: "Medio", score090: 2, comentario090: msg };
  }
}
