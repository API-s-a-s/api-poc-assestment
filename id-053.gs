/**
 * Estrategia para auditar la configuración de instalación de Marketplace.
 * Evalúa si los usuarios pueden instalar aplicaciones libremente o de forma restringida.
 * Utiliza Cloud Identity API en memoria
 */
class MarketplaceInstallPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-053", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario053",
        riskKey: "riesgo053",
        scoreKey: "score053"
      }
    ];

    super("Marketplace Install Policy Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Integración de aplicaciones";
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;

    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global.");
    }

    const targetPolicies = policies.filter(p => p.setting && p.setting.type === "workspace_marketplace.apps_access_options");

    let isSecure = false; 

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "workspace_marketplace.apps_access_options");
      if (rootPolicy && rootPolicy.setting) {
        const configNode = rootPolicy.setting.value || rootPolicy.setting;
        const settingStr = JSON.stringify(configNode).toUpperCase();

        if (settingStr.includes('RESTRICTED') || settingStr.includes('BLOCKED') || settingStr.includes('ALLOW_LISTED_APPS') || settingStr.includes('ALLOW_NONE')) {
          isSecure = true;
        }
      }
    }

    let respuestaConcreta;
    let riesgo053, comentario053;

    if (isSecure) {
      respuestaConcreta = "Instalaciones Restringidas";
      riesgo053 = "Bajo";
      comentario053 = "La política de acceso a Google Workspace Marketplace se encuentra configurada con parámetros restrictivos o de bloqueo, impidiendo instalaciones ilimitadas.";
    } else {
      respuestaConcreta = "Instalaciones Libres";
      riesgo053 = "Alto";
      comentario053 = "La política de acceso a Google Workspace Marketplace carece de restricciones explícitas, lo que permite a los usuarios finales la instalación libre e ilimitada.";
    }

    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario053: comentario053,
      riesgo053: riesgo053,
      score053: this.calcularScoreDeRiesgo(riesgo053)
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
    return { name: this.name, valorPrincipal: "ERROR", riesgo053: "Medio", score053: 2, comentario053: msg };
  }
}