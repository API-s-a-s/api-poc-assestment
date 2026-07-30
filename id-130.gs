/**
 * Estrategia para auditar los permisos de creación y edición de Google Sites.
 * Evalúa los parámetros allowSitesCreation y allowSitesModification.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/sites.sites_creation_and_modification
 */
class SitesCreationModificationStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-130", 
        valueKey: "valorPrincipal",
        noteKey: "comentario130",
        riskKey: "riesgo130",
        scoreKey: "score130"
      }
    ];

    super("Sites Creation and Modification Audit", configIDs);
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

    Logger.log(`[DEBUG ID-130] Total de políticas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes al entorno de Sites
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("sites.sites_creation_and_modification")
    );
    
    Logger.log(`[ID-130] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // LOG DE CONTROL: Si vino vacío en memoria, listamos qué hay de 'sites' disponible para diagnosticar
    if (targetPolicies.length === 0) {
      const sitesTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("sites"));
      Logger.log(`[DEBUG ID-130] [ALERT] Filtro en memoria vacío. Mapeo de tipos relacionados con 'sites' existentes: ${JSON.stringify(sitesTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-130] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*sites.sites_creation_and_modification.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-130] URL Generada para API: ${url}`);
        Logger.log(`[DEBUG ID-130] Filtro estructurado enviado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente lo que responde la API de Google en crudo
        Logger.log(`[DEBUG ID-130] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-130] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-130] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-130] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-130] Metadatos de políticas encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.setting?.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedCreation = null;
    let extractedModification = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "sites.sites_creation_and_modification");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        // LOG EXPLICITO: Ver la anatomía interna del nodo de configuración
        Logger.log(`[DEBUG ID-130] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-130] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación resiliente para allowSitesCreation (camelCase y snake_case)
        if (valueNode.allowSitesCreation !== undefined) {
          extractedCreation = valueNode.allowSitesCreation;
        } else if (valueNode.allow_sites_creation !== undefined) {
          extractedCreation = valueNode.allow_sites_creation;
        }

        // Verificación resiliente para allowSitesModification (camelCase y snake_case)
        if (valueNode.allowSitesModification !== undefined) {
          extractedModification = valueNode.allowSitesModification;
        } else if (valueNode.allow_sites_modification !== undefined) {
          extractedModification = valueNode.allow_sites_modification;
        }
        
        Logger.log(`[DEBUG ID-130] Valores finales extraídos -> Creación: ${extractedCreation} | Modificación: ${extractedModification}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluación cruzada de variables booleanas estrictas
    if (extractedCreation === true) {
      respuestaConcreta = extractedModification ? "Permitir creación y edición" : "Solo permitir creación";
      riesgo = "Alto";
      comentario = "La creación de nuevos sitios está habilitada de forma irrestricta. Esto permite que cualquier usuario interno genere portales de phishing aprovechando la reputación y confianza del dominio.";
    } else if (extractedCreation === false) {
      if (extractedModification === true) {
        respuestaConcreta = "Solo permitir edición de sitios";
        riesgo = "Medio";
        comentario = "La creación de nuevos sitios está bloqueada de forma segura, mitigando vectores de phishing de nuevos dominios.";
      } else {
        respuestaConcreta = "Desactivado";
        riesgo = "Bajo";
        comentario = "Tanto la creación como la edición de sitios están completamente restringidas.";
      }
    } else {
      // Manejo de valores heredados o comportamiento por defecto (Google suele permitir la creación de forma nativa)
      respuestaConcreta = "Validar manualmente";
      riesgo = "Alto";
      comentario = "No se encontraron políticas explícitas en la API para esta OU, lo que expone al dominio a la creación libre de sitios por parte de cualquier empleado.";
    }

    Logger.log(`[LOG] Sites Creation and Modification Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Creation: ${extractedCreation} | Modification: ${extractedModification}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario130: comentario,
      riesgo130: riesgo,
      score130: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-130] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo130: "Medio", score130: 2, comentario130: msg };
  }
}