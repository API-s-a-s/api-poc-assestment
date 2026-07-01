/**
 * Estrategia para auditar los permisos de acceso a las APIs de Google Cloud.
 * Verifica si hay servicios de GCP restringidos para aplicaciones de terceros.
 * Utiliza Cloud Identity API (consulta directa).
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

    // Enums de Google Cloud según respuesta de la API (ej: CLOUD_PLATFORM, CLOUD_BILLING)
    this.GOOGLE_CLOUD_SERVICES = [
      "CLOUD_PLATFORM", 
      "CLOUD_BILLING", 
      "CLOUD_ML", 
      "APPS_SCRIPT"
    ];
  }

  evaluateInMemory(globalContext) {
    const { auth, policies } = globalContext;
    if (!auth) return this._buildErrorResponse("Falta el contexto de autenticación (auth) en globalContext.");

    Logger.log(`[ID-045] Iniciando evaluación para api_controls.google_services (GCP)...`);

    let restrictedCount = 0;
    let totalServices = 0;
    let isCloudPlatformSecure = false;
    let isCloudBillingSecure = false;
    let restrictedServicesList = [];

    let rootPolicy = globalContext._tempGoogleServicesRootPolicy;

    // Si no está disponible en la caché temporal, procedemos a buscarlo o pedirlo
    if (!rootPolicy) {
      let servicePolicies = [];
      if (policies) {
        servicePolicies = policies.filter(p => {
          const st = (p.setting && p.setting.type) || "";
          return st === "settings/api_controls.google_services" || st.includes("api_controls.google_services");
        });
      }

      if (servicePolicies.length === 0) {
        try {
          const adminEmail = auth.getCurrentUserEmail(); 
          const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
            "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
          ]);

          const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*api_controls.google_services.*")`;
          const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

          const options = {
            method: "get",
            headers: { ...privilegedHeader, "Cache-Control": "no-cache" }
          };

          const response = this.fetchWithBackoff(url, options);
          const json = JSON.parse(response.getContentText());
          servicePolicies = json.policies || [];
        } catch (e) {
          Logger.log(`[ID-045] Error al consultar la API directamente: ${e.message}`);
          return this._buildErrorResponse(`Error al consultar la API: ${e.message}`);
        }
      }

      if (servicePolicies.length > 0) {
        rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(servicePolicies, "api_controls.google_services");
        if (!rootPolicy) {
          rootPolicy = PolicyReducerFactory.reduce(servicePolicies, "api_controls.google_services");
        }
        if (!rootPolicy && servicePolicies.length > 0) {
          rootPolicy = servicePolicies[0];
        }
      }
    } else {
      Logger.log(`[ID-045] Usando política temporal compartida por ID-044.`);
    }

    if (rootPolicy && rootPolicy.setting) {
      const configNode = rootPolicy.setting.value || rootPolicy.setting;
      const services = configNode.services || [];
      
      services.forEach(s => {
        const scopeGroup = (s.scopesGroup || s.scopes_group || s.service_name || s.name || "").toUpperCase();
        
        let isCloudService = false;
        for (const key of this.GOOGLE_CLOUD_SERVICES) {
          if (scopeGroup.includes(key)) {
            isCloudService = true;
            break;
          }
        }

        if (isCloudService) {
          totalServices++;
          // isEnabled === false significa restringido
          const isRestricted = s.isEnabled === false || s.is_enabled === false;
          
          if (isRestricted) {
            restrictedCount++;
            restrictedServicesList.push(scopeGroup);
            Logger.log(`[ID-045] Servicio GCP restringido detectado: ${scopeGroup}`);
            if (scopeGroup.includes("CLOUD_PLATFORM")) isCloudPlatformSecure = true;
            if (scopeGroup.includes("CLOUD_BILLING")) isCloudBillingSecure = true;
          }
        }
      });
    }

    let riesgo045, comentario045, valorPrincipalFormateado;
    valorPrincipalFormateado = `${restrictedCount} restringidos`;
    const appsBloqueadas = restrictedServicesList.length > 0 ? ` (Apps bloqueadas: ${restrictedServicesList.join(", ")})` : "";

    if (!isCloudPlatformSecure || !isCloudBillingSecure) {
      riesgo045 = "Alto";
      comentario045 = `La app ${appsBloqueadas}  se restringe contra terceros. `;
    } else {
      riesgo045 = "Bajo";
      comentario045 = `Cumplimiento Zero Trust: ${restrictedCount} servicios de Google Cloud (GCP) están restringidos correctamente frente a aplicaciones de terceros, protegiendo los entornos de desarrollo y facturación.${appsBloqueadas}`;
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