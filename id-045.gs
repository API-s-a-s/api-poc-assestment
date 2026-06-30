/**
 * Estrategia para auditar los permisos de acceso a las APIs de Google Cloud.
 * Verifica si hay servicios de GCP restringidos para aplicaciones de terceros.
 * Utiliza Cloud Identity API en memoria
 */
class GoogleCloudApiControlStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-045", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario045",
        riskKey: "riesgo045",
        scoreKey: "score045"
      }
    ];

    super("Google Cloud API Controls Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Integración de aplicaciones";
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    // CAMBIO EXTRA EXTRAORDINARIO: Apuntar al endpoint real de servicios unificados
    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").includes("api_controls.google_services"));

    let restrictedCount = 0;
    let totalServices = 0;
    let isCloudPlatformSecure = false;
    let isCloudBillingSecure = false;
    const cloudEnums = ["CLOUD_PLATFORM", "CLOUD_BILLING", "CLOUD_ML", "APPS_SCRIPT_RUNTIME", "APPS_SCRIPT_API"];

    if (targetPolicies.length > 0) {
      let rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "api_controls.google_services");
      
      // Fallback si la API de controles no devuelve la firma de rootPolicy clásica:
      if (!rootPolicy) {
        rootPolicy = PolicyReducerFactory.reduce(targetPolicies, "api_controls.google_services");
      }

      if (rootPolicy && rootPolicy.setting) {
        const configNode = rootPolicy.setting.value || rootPolicy.setting;
        const services = configNode.services || [];
        
        services.forEach(s => {
          const scopeGroup = (s.scopes_group || s.scopesGroup || "").toUpperCase();
          if (cloudEnums.includes(scopeGroup)) {
            totalServices++;
            const isRestricted = s.is_enabled === true || s.isEnabled === true;
            if (isRestricted) {
              restrictedCount++;
              if (scopeGroup === "CLOUD_PLATFORM") isCloudPlatformSecure = true;
              if (scopeGroup === "CLOUD_BILLING") isCloudBillingSecure = true;
            }
          }
        });
      }
    }

    let riesgo045, comentario045, valorPrincipalFormateado;
    if (!isCloudPlatformSecure || !isCloudBillingSecure) {
      riesgo045 = "Alto";
      valorPrincipalFormateado = "0 restringidos";
      comentario045 = "Vulnerabilidad Crítica de Infraestructura (Shadow IT en GCP): Los alcances globales de Google Cloud Platform (GCP) o Facturación no se encuentran restringidos. Tokens de terceros pueden tomar control de entornos de cómputo (Cryptojacking).";
    } else {
      riesgo045 = "Bajo";
      valorPrincipalFormateado = `${restrictedCount} restringidos`;
      comentario045 = `Cumplimiento Zero Trust: ${restrictedCount} de ${totalServices} servicios de Google Cloud (GCP) están restringidos correctamente frente a aplicaciones de terceros, protegiendo los entornos de desarrollo y facturación.`;
    }

    return { name: this.name, valorPrincipal: valorPrincipalFormateado, comentario045: comentario045, riesgo045: riesgo045, score045: this.calcularScoreDeRiesgo(riesgo045) };
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
    return { name: this.name, valorPrincipal: "ERROR", riesgo045: "Medio", score045: 2, comentario045: msg };
  }
}