/**
 * Estrategia para auditar el uso compartido y publicación de Google Sites (gestionado en el backend de Drive).
 * Evalúa los parámetros externalSharingMode y allowPublishingFiles.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.external_sharing
 */
class SitesDriveExternalSharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-131", 
        valueKey: "valorPrincipal",
        noteKey: "comentario131",
        riskKey: "riesgo131",
        scoreKey: "score131"
      }
    ];

    super("Sites Drive External Sharing Audit", configIDs);
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

    Logger.log(`[DEBUG ID-131] Total de políticas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes al entorno de Drive & Docs que gobiernan a Sites
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("drive_and_docs.external_sharing")
    );
    
    Logger.log(`[ID-131] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // LOG DE CONTROL: Si vino vacío en memoria, listamos qué hay de 'drive' disponible para diagnosticar
    if (targetPolicies.length === 0) {
      const driveTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("drive"));
      Logger.log(`[DEBUG ID-131] [ALERT] Filtro en memoria vacío. Mapeo de tipos relacionados con 'drive' existentes: ${JSON.stringify(driveTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-131] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*drive_and_docs.external_sharing.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-131] URL Generada para API: ${url}`);
        Logger.log(`[DEBUG ID-131] Filtro estructurado enviado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente lo que responde la API de Google en crudo
        Logger.log(`[DEBUG ID-131] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-131] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-131] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-131] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-131] Metadatos de políticas encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.setting?.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedSharingMode = null;
    let extractedPublishing = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "drive_and_docs.external_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        // LOG EXPLICITO: Ver la anatomía interna del nodo de configuración
        Logger.log(`[DEBUG ID-131] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-131] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación resiliente para externalSharingMode (camelCase y snake_case)
        if (valueNode.externalSharingMode !== undefined) {
          extractedSharingMode = valueNode.externalSharingMode;
        } else if (valueNode.external_sharing_mode !== undefined) {
          extractedSharingMode = valueNode.external_sharing_mode;
        }

        // Verificación resiliente para allowPublishingFiles (camelCase y snake_case)
        if (valueNode.allowPublishingFiles !== undefined) {
          extractedPublishing = valueNode.allowPublishingFiles;
        } else if (valueNode.allow_publishing_files !== undefined) {
          extractedPublishing = valueNode.allow_publishing_files;
        }
        
        Logger.log(`[DEBUG ID-131] Valores finales extraídos -> Modo Compartir: ${extractedSharingMode} | Permitir Publicación: ${extractedPublishing}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluación cruzada de variables (Enum + Booleano)
    if (extractedPublishing === true) {
      respuestaConcreta = `Publicación Permitida (${extractedSharingMode || "ON"})`;
      riesgo = "Alto";
      commentario = "Debido a que Google Sites se gestiona de forma nativa en la infraestructura de Drive, permitir la publicación de archivos habilita que los sitios sean indizados por motores de búsqueda públicos sin requerir autenticación corporativa. Esto expone a la organización a que entidades maliciosas generen portales de phishing bajo un dominio de alta reputación.";
    } else if (extractedSharingMode === "OFF") {
      respuestaConcreta = "Uso compartido externo desactivado";
      riesgo = "Bajo";
      comentario = "El intercambio externo y la publicación de archivos de Drive (incluidos Google Sites) están completamente bloqueados. Los sitios web creados solo pueden ser visualizados por miembros autenticados del inquilino, garantizando un perímetro estricto.";
    } else if (extractedPublishing === false) {
      respuestaConcreta = `Compartición Externa Activa / Publicación Bloqueada`;
      riesgo = "Medio";
      comentario = "Se permite compartir archivos con usuarios externos específicos, pero la capacidad de publicar Google Sites de manera abierta hacia internet sin autenticación está bloqueada de forma segura. Mitiga la indización en motores de búsqueda.";
    } else {
      // Manejo de valores por defecto o indefinidos
      respuestaConcreta = "Revisión manual / Por defecto";
      riesgo = "Medio";
      comentario = "No se detectaron políticas explícitas en la API de Cloud Identity para el control de intercambio perimetral de Drive. Se recomienda verificar directamente la consola de administración en la sección de Drive y Docs > Opciones de uso compartido.";
    }

    Logger.log(`[LOG] Sites Drive External Sharing Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Mode: ${extractedSharingMode} | Pub: ${extractedPublishing}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario131: commentario,
      riesgo131: riesgo,
      score131: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-131] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo131: "Medio", score131: 2, comentario131: msg };
  }
}