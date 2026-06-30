/**
 * Estrategia para auditar la confianza de las aplicaciones propiedad del dominio.
 * Evalúa si las apps internas tienen acceso confiable por defecto.
 * Utiliza Cloud Identity API en memoria
 */
class InternalAppsTrustStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-047", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario047",
        riskKey: "riesgo047",
        scoreKey: "score047"
      }
    ];

    super("Internal Apps Trust Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Integración de aplicaciones";
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;

    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global.");
    }

    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").includes("api_controls.internal_apps"));

    let isTrustedByDefault = false;
    let existePoliticaExplicita = false;

    if (targetPolicies.length > 0) {
      existePoliticaExplicita = true;
      let rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "api_controls.internal_apps");
      
      if (!rootPolicy) {
         rootPolicy = PolicyReducerFactory.reduce(targetPolicies, "api_controls.internal_apps");
      }

      if (rootPolicy && rootPolicy.setting) {
        const configNode = rootPolicy.setting.value || rootPolicy.setting;
        const internalNode = configNode.internalApps || configNode.internal_apps || configNode;
        
        const isTrusted = internalNode.trust_internal_apps === true || internalNode.trustInternalApps === true;
        if (isTrusted) {
          isTrustedByDefault = true;
        }
      }
    }

    let respuestaConcreta;
    let riesgo047, comentario047;

    if (isTrustedByDefault) {
      respuestaConcreta = "Confiable por Defecto";
      riesgo047 = "Alto";
      comentario047 = "La política se encuentra configurada para confiar de manera predeterminada en TODAS las aplicaciones desarrolladas internamente y propiedad del dominio, permitiéndoles el acceso sin autorización granular.";
    } else if (!existePoliticaExplicita) {
      respuestaConcreta = "Requiere Autorización (Predeterminado)";
      riesgo047 = "Medio";
      comentario047 = "No hay política explícita. Por defecto de Google, las aplicaciones internas podrían no ser confiables automáticamente y requerir revisión, pero se sugiere establecerlo explícitamente.";
    } else {
      respuestaConcreta = "Requiere Autorización";
      riesgo047 = "Bajo";
      comentario047 = "Existe una directiva técnica configurada que deniega explícitamente la confianza automática a las aplicaciones internas, obligando a autorización individual.";
    }

    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario047: comentario047,
      riesgo047: riesgo047,
      score047: this.calcularScoreDeRiesgo(riesgo047)
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
    return { name: this.name, valorPrincipal: "ERROR", riesgo047: "Medio", score047: 2, comentario047: msg };
  }
}