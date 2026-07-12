/**
 * Estrategia para auditar el acceso a servicios no cubiertos por los Términos de Servicio (TdS) empresariales.
 * Evalúa las variables de habilitación (is_enabled) y restricciones empresariales lógicas.
 * Utiliza Cloud Identity Policy API (v1).
 * Ubicación en Consola: Additional Google services
 * Scope: Domain
 */
class AdditionalServicesToSAuditStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-139", 
        valueKey: "valorPrincipal",
        noteKey: "comentario139",
        riskKey: "riesgo139",
        scoreKey: "score139"
      }
    ];

    super("Additional Google Services Terms of Service Access Audit", configIDs);
    this.category = "Servicios adicionales";
    this.customerId = customerId;
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  evaluateInMemory(globalContext) {
    const { policies, auth } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    Logger.log(`[DEBUG ID-139] Total de políticas recibidas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes a las restricciones de servicios empresariales lógicos y api_controls
    let targetPolicies = policies.filter(p => 
      p.setting && (
        (p.setting.type || "").endsWith("enterprise_service_restrictions") || 
        (p.setting.type || "").endsWith("api_controls.google_services")
      )
    );
    
    Logger.log(`[ID-139] Se encontraron ${targetPolicies.length} políticas en memoria para este filtro.`);
    
    // LOG DE CONTROL: Si viene vacío en memoria, listamos las políticas que tengan coincidencias para diagnóstico
    if (targetPolicies.length === 0) {
      const relatedTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && (t.toLowerCase().includes("service") || t.toLowerCase().includes("api_controls")));
      Logger.log(`[DEBUG ID-139] [ALERT] Filtro masivo vacío. Mapeo de tipos relacionados en memoria: ${JSON.stringify(relatedTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-139] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && (setting.type.matches(".*enterprise_service_restrictions.*") || setting.type.matches(".*api_controls.google_services.*"))`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-139] URL de consulta directa generada: ${url}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente qué es lo que llega de la API de Google
        Logger.log(`[DEBUG ID-139] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-139] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-139] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-139] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-139] Metadatos de políticas de control de servicios encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.setting?.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedRestriction = null;
    let extractedIsEnabled = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      // Intentamos resolver utilizando el reductor por defecto
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "enterprise_service_restrictions") || targetPolicies[0];
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        // LOG EXPLICITO: Ver la anatomía interna del nodo de configuración
        Logger.log(`[DEBUG ID-139] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-139] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación resiliente para unconfigured_third_party_apps (snake_case y camelCase)
        if (valueNode.unconfigured_third_party_apps !== undefined) {
          extractedRestriction = valueNode.unconfigured_third_party_apps;
        } else if (valueNode.unconfiguredThirdPartyApps !== undefined) {
          extractedRestriction = valueNode.unconfiguredThirdPartyApps;
        }

        // Verificación de variables de habilitación (is_enabled / isEnabled)
        if (valueNode.is_enabled !== undefined) {
          extractedIsEnabled = valueNode.is_enabled;
        } else if (valueNode.isEnabled !== undefined) {
          extractedIsEnabled = valueNode.isEnabled;
        } else if (valueNode.services && Array.isArray(valueNode.services)) {
          // Si es un array de servicios (como api_controls.google_services), consideramos habilitado si alguno de los servicios críticos está habilitado
          const activeServices = valueNode.services.filter(s => s.isEnabled !== false && s.is_enabled !== false);
          extractedIsEnabled = activeServices.length > 0;
        }
        
        Logger.log(`[DEBUG ID-139] Valores extraídos finales -> Restricción: ${extractedRestriction} | Habilitado: ${extractedIsEnabled}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluación lógica de las variables de restricción y habilitación corporativa
    if (extractedRestriction === "DENY" || extractedRestriction === "RESTRICTED" || extractedIsEnabled === false) {
      respuestaConcreta = "Acceso Restringido (Denegación Implícita)";
      riesgo = "Bajo";
      comentario = "Configuración correcta del perímetro global del dominio. Se restringe lógicamente el acceso a las aplicaciones adicionales no configuradas explícitamente. Esto implementa una política de denegación implícita que protege al Directorio de Workspace contra el procesamiento involuntario de datos corporativos en plataformas que carecen de SLAs empresariales o certificaciones normativas (HIPAA, FedRAMP).";
    } else if (extractedRestriction === "ALLOW" || extractedRestriction === "UNRESTRICTED" || extractedIsEnabled === true) {
      respuestaConcreta = "Acceso Abierto (Permisivo)";
      riesgo = "Alto";
      comentario = "Se permite de forma irrestricta el acceso de los usuarios a servicios auxiliares y adicionales de consumo general de Google (YouTube, Blogger, herramientas de IA no empresariales). Estas plataformas eluden los Acuerdos de Nivel de Servicio (SLA) centrales del inquilino y exponen datos corporativos a enrutamientos fuera del cumplimiento corporativo.";
    } else {
      // Comportamiento permisivo por defecto si Google no reporta políticas explícitas
      respuestaConcreta = "Acceso Abierto (Valor por defecto)";
      riesgo = "Alto";
      comentario = "No se detectaron directivas explícitas de control a nivel de Tenant. Google Workspace mantiene de forma predeterminada activo y abierto el acceso a los servicios adicionales de nivel de consumo, vulnerando los principios de menor privilegio y contención legal del inquilino completo.";
    }

    Logger.log(`[LOG] Servicios Adicionales ToS Access Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Restricción: ${extractedRestriction} | Habilitado: ${extractedIsEnabled}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario139: comentario,
      riesgo139: riesgo,
      score139: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-139] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo139: "Medio", score139: 2, comentario139: msg };
  }
}