/**
 * Estrategia para auditar si se permite que aplicaciones de terceros accedan a los datos del directorio interno.
 * Evalúa el parámetro sharing_option.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/directory.external_directory_sharing
 */
class ContactsExternalDirectorySharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-123", 
        valueKey: "valorPrincipal",
        noteKey: "comentario123",
        riskKey: "riesgo123",
        scoreKey: "score123"
      }
    ];

    super("Contacts External Directory Sharing Audit", configIDs);
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

    Logger.log(`[DEBUG ID-123] Total de políticas recibidas en memoria global: ${policies.length}`);

    // Filtramos las políticas pertenecientes al sub-entorno de Directory (external sharing)
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("directory.external_directory_sharing")
    );
    
    Logger.log(`[ID-123] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // INSPECCIÓN 1: Si vino vacío en memoria, veamos qué tipos de Directory sí están viniendo en el bulk
    if (targetPolicies.length === 0) {
      const directoryTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("directory"));
      Logger.log(`[DEBUG ID-123] [ALERT] Filtro masivo vacío. Tipos de 'directory' que SÍ están en memoria: ${JSON.stringify(directoryTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-123] [WARNING] La API masiva no trajo configuraciones. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*directory.external_directory_sharing.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-123] URL de consulta directa: ${url}`);
        Logger.log(`[DEBUG ID-123] Filtro aplicado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true // Evita que el script muera si la API responde 400 o 404, permitiendo ver el error
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // INSPECCIÓN 2: Imprimir la respuesta RAW literal del servidor de Google
        Logger.log(`[DEBUG ID-123] Respuesta RAW de Google API: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-123] [ERROR API] Google devolvió un error estructurado: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-123] [SUCCESS] API directa parseada. Encontradas: ${targetPolicies.length} políticas.`);
      } catch (e) {
        Logger.log(`[ID-123] Error crítico al ejecutar la petición directa: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-123] Detalles de las políticas objetivo: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.setting?.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedValue = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "directory.external_directory_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        // INSPECCIÓN 3: Analizar cómo estructuró Google los nodos internos de la política devuelta
        Logger.log(`[DEBUG ID-123] Estructura completa de rootPolicy.setting: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-123] Estructura de valueNode seleccionado: ${JSON.stringify(valueNode)}`);
        
        // Verificación de sharing_option
        if (valueNode.sharing_option !== undefined) {
          extractedValue = valueNode.sharing_option;
        } else if (valueNode.sharingOption !== undefined) {
          extractedValue = valueNode.sharingOption;
        }
        
        Logger.log(`[DEBUG ID-123] Valor extraído final: ${extractedValue}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    if (extractedValue === "REQUESTER_BASIC_PROFILE_ONLY") {
      respuestaConcreta = "Sólo perfil básico del solicitante";
      riesgo = "Bajo";
      comentario = "La configuración restringe el acceso de aplicaciones externas únicamente a los datos básicos del perfil del solicitante. Esto minimiza el riesgo de que un tercero descargue el directorio completo de la organización.";
    } else if (extractedValue === "ORGANIZATION_DIRECTORY_DATA") {
      respuestaConcreta = "Datos del directorio de la organización";
      riesgo = "Alto";
      comentario = "Se permite a las aplicaciones externas acceder a todos los datos del directorio de la organización. Esto expone nombres, correos electrónicos, alias, y relaciones jerárquicas de todos los usuarios de la empresa, facilitando ataques dirigidos (spear phishing) o exfiltración masiva.";
    } else if (extractedValue === "SHARING_OPTION_UNSPECIFIED") {
      respuestaConcreta = "No especificado";
      riesgo = "Medio";
      comentario = "La opción de uso compartido no está explícitamente especificada en la política. Se recomienda forzar a 'Sólo perfil básico del solicitante' para garantizar la postura de menor privilegio.";
    } else {
      // Fallback de gobernanza: Si no se definen políticas explícitas, Google Workspace aplica el valor 
      // predeterminado del sistema que es permitir el acceso a los datos del directorio (ORGANIZATION_DIRECTORY_DATA),
      // lo cual representa una postura insegura por defecto.
      respuestaConcreta = "Datos del directorio de la organización (Valor por defecto)";
      riesgo = "Alto";
      comentario = "No se encontraron políticas explícitas en la API. Por defecto, Google Workspace permite que aplicaciones de terceros accedan a todos los datos del directorio de la organización, lo que expone nombres, correos y jerarquías corporativas.";
    }

    Logger.log(`[LOG] Contacts External Directory Sharing Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedValue}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario123: comentario,
      riesgo123: riesgo,
      score123: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-123] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo123: "Medio", score123: 2, comentario123: msg };
  }
}