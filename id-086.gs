/**
 * Estrategia para auditar la restricción de entrega en Gmail.
 * ID-086: Restringir la entrega.
 */
class GmailRestrictDeliveryStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-086", 
        valueKey: "valorPrincipal",
        noteKey: "comentario086",
        riskKey: "riesgo086",
        scoreKey: "score086"
      }
    ];
    super("Gmail Restrict Delivery Audit", configIDs);
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
      Logger.log(`[WARN] Reports API fallback failed: ${e.message}`);
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    const restrictPolicies = policies.filter(p => p.setting && ((p.setting.type || "").endsWith("gmail.restrict_delivery") || (p.setting.type || "").endsWith("gmail.delivery_restriction")));
    let rulesCount = 0;
    let dataSource = "Memory";
    let rawData = null;

    if (restrictPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(restrictPolicies, restrictPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-086] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-086] valueNode: ${JSON.stringify(valueNode)}`);
        const rules = valueNode.rules || valueNode.settingRules || [];
        rulesCount = rules.length;
      }
    } else {
      Logger.log(`[LOG] Restrict Delivery no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Restrict delivery");
      if (logResult.found) {
        // En reportes, inferimos si hay al menos una regla
        rulesCount = (logResult.enabled === true || (logResult.newValue && logResult.newValue !== "")) ? 1 : 0;
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        rulesCount = 0;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let riesgo086, comentario086;

    if (rulesCount === 0) {
      riesgo086 = "Bajo";
      comentario086 = `No se detectaron reglas de Restricción de Entrega (Fuente: ${dataSource}). Esto es normal para dominios públicos donde los usuarios pueden enviar y recibir correos de cualquier origen. Si este dominio debería ser exclusivamente interno, la falta de estas reglas constituye un riesgo Medio.`;
    } else {
      riesgo086 = "Medio";
      comentario086 = `Se encontraron ${rulesCount} reglas de Restricción de Entrega (Fuente: ${dataSource}). La organización está limitando proactivamente qué dominios o direcciones pueden enviar/recibir correos de ciertos usuarios, lo que es excelente para prevenir fuga de datos. Se requiere auditar las listas blancas para evitar que listas obsoletas permitan bypass.`;
    }

    Logger.log(`[LOG] Restrict Delivery Audit: ${rulesCount} reglas detectadas. | Riesgo: ${riesgo086}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: rulesCount,
      comentario086: comentario086,
      riesgo086: riesgo086,
      score086: this.calcularScoreDeRiesgo(riesgo086)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo086: "Medio", score086: 2, comentario086: msg };
  }
}
