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
      
      const response = AdminReports.Activities.list("all", "admin", {
        eventName: "CHANGE_GMAIL_SETTING",
        startTime: sixMonthsAgo.toISOString(),
        maxResults: 50
      });
      
      if (response.items && response.items.length > 0) {
        for (const item of response.items) {
          for (const event of item.events) {
            if (event.name === "CHANGE_GMAIL_SETTING") {
              const paramName = event.parameters.find(p => p.name === "SETTING_NAME");
              const paramEnabled = event.parameters.find(p => p.name === "SETTING_ENABLED");
              const paramNewValue = event.parameters.find(p => p.name === "NEW_VALUE");
              
              if (paramName && paramName.value && paramName.value.toLowerCase().includes(settingName.toLowerCase())) {
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
      return { found: false };
    } catch (e) {
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    const routingPolicies = policies.filter(p => p.setting && ((p.setting.type || "").endsWith("gmail.routing") || (p.setting.type || "").endsWith("gmail.routing_rules")));
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
        const rules = valueNode.rules || valueNode.settingRules || [];
        rulesCount = rules.length;
      }
    } else {
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
      comentario090 = `Se detectaron ${rulesCount} reglas de enrutamiento adicionales (Fuente: ${dataSource}). El enrutamiento en Gmail permite desviar o duplicar (Dual Delivery) el flujo de correos hacia destinos específicos. Es crucial auditar regularmente estas reglas para garantizar que no existan desviaciones ocultas creadas por administradores malintencionados o cuentas comprometidas para robar copias del correo entrante/saliente.`;
    } else {
      riesgo090 = "Bajo";
      comentario090 = `No se detectaron reglas de enrutamiento adicionales (Fuente: ${dataSource}). El flujo de correo se mantiene estándar y nativo, mitigando el riesgo de que correos sean duplicados y enviados sigilosamente a servidores externos no autorizados.`;
    }

    Logger.log(`[LOG] Routing Rules Audit: ${rulesCount} reglas detectadas. | Riesgo: ${riesgo090}`);

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
