/**
 * Estrategia para auditar el cumplimiento de transporte seguro TLS.
 * ID-087: Reglas de cumplimiento de transporte seguro (TLS).
 */
class GmailTlsComplianceStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-087", 
        valueKey: "valorPrincipal",
        noteKey: "comentario087",
        riskKey: "riesgo087",
        scoreKey: "score087"
      }
    ];
    super("Gmail TLS Compliance Audit", configIDs);
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

    const tlsPolicies = policies.filter(p => p.setting && ((p.setting.type || "").endsWith("gmail.secure_transport") || (p.setting.type || "").endsWith("gmail.tls_compliance")));
    let rulesCount = 0;
    let dataSource = "Memory";
    let rawData = null;

    if (tlsPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(tlsPolicies, tlsPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-087] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-087] valueNode: ${JSON.stringify(valueNode)}`);
        const rules = valueNode.rules || valueNode.settingRules || [];
        rulesCount = rules.length;
      }
    } else {
      const logResult = this.checkAdminReportsForSetting("Secure transport");
      if (logResult.found) {
        rulesCount = (logResult.enabled === true || (logResult.newValue && logResult.newValue !== "")) ? 1 : 0;
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        rulesCount = 0;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let riesgo087, comentario087;

    if (rulesCount > 0) {
      riesgo087 = "Bajo";
      comentario087 = `Se encontraron ${rulesCount} reglas de Cumplimiento TLS (Fuente: ${dataSource}). La organización está forzando conexiones cifradas estrictas con dominios de socios críticos, garantizando que el correo no se transmita nunca en texto plano si el servidor de destino intenta degradar la conexión (ataque downgrade).`;
    } else {
      riesgo087 = "Medio";
      comentario087 = `No se detectaron reglas explícitas de cumplimiento de transporte seguro (TLS) (Fuente: ${dataSource}). Aunque Gmail usa TLS Oportunista para el 100% de sus conexiones, la ausencia de reglas estrictas de cumplimiento implica que, si un dominio de destino no soporta TLS, el correo se entregará en texto plano sin bloquearse.`;
    }

    Logger.log(`[LOG] TLS Compliance Audit: ${rulesCount} reglas detectadas. | Riesgo: ${riesgo087}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: rulesCount,
      comentario087: comentario087,
      riesgo087: riesgo087,
      score087: this.calcularScoreDeRiesgo(riesgo087)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo087: "Medio", score087: 2, comentario087: msg };
  }
}
