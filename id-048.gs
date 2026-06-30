/**
 * Estrategia para auditar el mensaje de visualización personalizado.
 * Evalúa si existe un mensaje corporativo cuando se bloquea el acceso a una App.
 * Utiliza Cloud Identity API en memoria
 */
class CustomUserMessageApiStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-048", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario048",
        riskKey: "riesgo048",
        scoreKey: "score048"
      }
    ];

    super("Custom User Message API Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Integración de aplicaciones";
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;

    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global.");
    }

    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").includes("api_controls.custom_user_message"));

    let customMessage = "";

    if (targetPolicies.length > 0) {
      let rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "api_controls.custom_user_message");
      
      if (!rootPolicy) {
         rootPolicy = PolicyReducerFactory.reduce(targetPolicies, "api_controls.custom_user_message");
      }

      if (rootPolicy && rootPolicy.setting) {
        const configNode = rootPolicy.setting.value || rootPolicy.setting;
        const msgNode = configNode.customUserMessage || configNode.custom_user_message || configNode;
        customMessage = msgNode.error_text || msgNode.errorText || "";
      }
    }

    let respuestaConcreta;
    let riesgo048, comentario048;

    if (customMessage && customMessage.trim() !== "") {
      respuestaConcreta = "Mensaje Personalizado Configurado";
      riesgo048 = "Bajo";
      comentario048 = "Existe una directiva con un mensaje corporativo personalizado configurado que se mostrará a los usuarios cuando se bloquee su intento de acceso a aplicaciones de terceros no autorizadas.";
    } else {
      respuestaConcreta = "Mensaje Predeterminado";
      riesgo048 = "Medio";
      comentario048 = "No existe un mensaje corporativo personalizado configurado; el sistema utilizará el mensaje de error estándar de Google cuando se bloquee el acceso a una aplicación.";
    }

    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario048: comentario048,
      riesgo048: riesgo048,
      score048: this.calcularScoreDeRiesgo(riesgo048)
    };
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo048: "Medio", score048: 2, comentario048: msg };
  }
}