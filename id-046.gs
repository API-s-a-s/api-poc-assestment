/**
 * Estrategia para auditar la configuración de aplicaciones de terceros no configuradas.
 * Evalúa si el acceso por defecto es restringido o ilimitado.
 * Utiliza Cloud Identity API en memoria
 */
class UnconfiguredAppsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-046", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario046",
        riskKey: "riesgo046",
        scoreKey: "score046"
      }
    ];

    super("Unconfigured Third Party Apps Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Integración de aplicaciones";
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;

    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global.");
    }

    const targetPolicies = policies.filter(p => p.setting && p.setting.type === "api_controls.unconfigured_third_party_apps");

    let accessLevel = "Ilimitado";

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "api_controls.unconfigured_third_party_apps");
      if (rootPolicy && rootPolicy.setting) {
        const configNode = rootPolicy.setting.value || rootPolicy.setting;
        const unconfiguredSetting = configNode.unconfiguredThirdPartyApps || configNode.unconfigured_third_party_apps || configNode;
        
        if (unconfiguredSetting.accessLevel === "RESTRICTED" || unconfiguredSetting.access_level === "RESTRICTED") {
          accessLevel = "Restringido";
        }
      }
    }

    let riesgo046, comentario046;

    if (accessLevel === "Restringido") {
      riesgo046 = "Bajo";
      comentario046 = "La política de control de acceso para aplicaciones de terceros no configuradas está establecida en nivel RESTRINGIDO. Es decir, requieren revisión explícita.";
    } else {
      riesgo046 = "Alto";
      comentario046 = "Las aplicaciones de terceros no configuradas tienen acceso ILIMITADO o no hay política que lo bloquee, lo que representa un riesgo significativo de exposición de datos.";
    }

    return {
      name: this.name,
      valorPrincipal: accessLevel,
      comentario046: comentario046,
      riesgo046: riesgo046,
      score046: this.calcularScoreDeRiesgo(riesgo046)
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
    return { name: this.name, valorPrincipal: "ERROR", riesgo046: "Medio", score046: 2, comentario046: msg };
  }
}