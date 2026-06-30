/**
 * Estrategia para auditar la configuración del Gateway de entrada en Gmail.
 * ID-077: Gateway de entrada (Inbound Gateway).
 */
class GmailInboundGatewayStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-077", 
        valueKey: "valorPrincipal",
        noteKey: "comentario077",
        riskKey: "riesgo077",
        scoreKey: "score077"
      }
    ];
    super("Gmail Inbound Gateway Audit", configIDs);
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

    const inboundPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.inbound_gateway"));
    let isInboundGatewayEnabled = false;
    let dataSource = "Memory";
    let rawData = null;

    if (inboundPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(inboundPolicies, "gmail.inbound_gateway");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-077] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-077] valueNode: ${JSON.stringify(valueNode)}`);
        if (valueNode.gatewayIps && valueNode.gatewayIps.length > 0) {
          isInboundGatewayEnabled = true;
        }
      }
    } else {
      Logger.log(`[LOG] Inbound Gateway no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Inbound Gateway");
      if (logResult.found) {
        isInboundGatewayEnabled = logResult.enabled === true || (logResult.newValue && logResult.newValue.toLowerCase() === "true");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        // Por defecto, las organizaciones NO tienen un gateway de entrada configurado
        isInboundGatewayEnabled = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo077, comentario077;

    if (isInboundGatewayEnabled) {
      respuestaConcreta = "Configurado";
      riesgo077 = "Medio"; // Riesgo medio porque debe revisarse que las IPs sean estrictamente conocidas y seguras
      comentario077 = `Se ha detectado la configuración de un Gateway de Entrada (Inbound Gateway) (Fuente: ${dataSource}). Todo el correo entrante se enruta primero a través de servidores o appliances de terceros. Se recomienda encarecidamente auditar las IPs configuradas en el gateway y asegurarse de que la opción 'Rechazar correos de servidores que no sean el gateway de entrada' esté activa para evitar que los atacantes evadan el appliance saltando directamente a los servidores de Google.`;
    } else {
      respuestaConcreta = "No Configurado";
      riesgo077 = "Bajo";
      comentario077 = `No se detectó un Gateway de Entrada configurado (Fuente: ${dataSource}). El tráfico de correo entrante fluye directamente hacia los servidores de Google, lo que permite que los controles de reputación y validaciones nativas operen sin interferencia de terceros.`;
    }

    Logger.log(`[LOG] Inbound Gateway Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo077}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario077: comentario077,
      riesgo077: riesgo077,
      score077: this.calcularScoreDeRiesgo(riesgo077)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo077: "Medio", score077: 2, comentario077: msg };
  }
}
