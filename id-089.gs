/**
 * Estrategia para auditar la configuración de Gateway de salida.
 * ID-089: Gateway de salida.
 */
class GmailOutboundGatewayStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-089", 
        valueKey: "valorPrincipal",
        noteKey: "comentario089",
        riskKey: "riesgo089",
        scoreKey: "score089"
      }
    ];
    super("Gmail Outbound Gateway Audit", configIDs);
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

    const outboundPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.outbound_gateway"));
    let isOutboundConfigured = false;
    let dataSource = "Memory";
    let rawData = null;

    if (outboundPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(outboundPolicies, "gmail.outbound_gateway");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-089] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-089] valueNode: ${JSON.stringify(valueNode)}`);
        if (valueNode.gatewayIp || (valueNode.routes && valueNode.routes.length > 0)) {
          isOutboundConfigured = true;
        }
      }
    } else {
      const logResult = this.checkAdminReportsForSetting("Outbound gateway");
      if (logResult.found) {
        isOutboundConfigured = logResult.enabled === true || (logResult.newValue && logResult.newValue !== "");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        isOutboundConfigured = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo089, comentario089;

    if (isOutboundConfigured) {
      respuestaConcreta = "Configurado";
      riesgo089 = "Medio"; // Riesgo medio porque requiere auditoría para asegurar que el appliance tercero es seguro y soporta TLS.
      comentario089 = `Se ha detectado un Gateway de Salida configurado (Fuente: ${dataSource}). Todo el correo saliente de la organización es retransmitido a través de servidores externos antes de ser entregado a Internet. Es vital auditar que estos servidores externos no estén comprometidos y que admitan encriptación TLS para evitar exfiltración masiva o suplantación en nombre de la empresa.`;
    } else {
      respuestaConcreta = "No Configurado";
      riesgo089 = "Bajo";
      comentario089 = `No se detectó un Gateway de Salida configurado (Fuente: ${dataSource}). El tráfico saliente de correo se enruta directamente desde la infraestructura segura de Google, lo que minimiza puntos de falla y dependencias de terceros para el envío.`;
    }

    Logger.log(`[LOG] Outbound Gateway Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo089}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario089: comentario089,
      riesgo089: riesgo089,
      score089: this.calcularScoreDeRiesgo(riesgo089)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo089: "Medio", score089: 2, comentario089: msg };
  }
}
