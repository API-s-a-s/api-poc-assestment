/**
 * Estrategia para auditar si los propietarios de grupos pueden permitir miembros externos.
 * Evalúa el parámetro owners_can_allow_external_members.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/groups_for_business.groups_sharing
 */
class GroupsSharingExternalMembersStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-124", 
        valueKey: "valorPrincipal",
        noteKey: "comentario124",
        riskKey: "riesgo124",
        scoreKey: "score124"
      }
    ];

    super("Groups Sharing External Members Audit", configIDs);
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

    Logger.log(`[DEBUG ID-124] Total de políticas recibidas en memoria global: ${policies.length}`);

    // Filtramos las políticas pertenecientes al sub-entorno de Groups (external members)
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("groups_for_business.groups_sharing")
    );
    
    Logger.log(`[ID-124] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // Inspección si vino vacío en memoria masiva
    if (targetPolicies.length === 0) {
      const groupTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("group"));
      Logger.log(`[DEBUG ID-124] [ALERT] Filtro masivo vacío. Tipos de 'groups' en memoria: ${JSON.stringify(groupTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-124] [WARNING] La API masiva no trajo configuraciones. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*groups_for_business.groups_sharing.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-124] URL de consulta directa: ${url}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        Logger.log(`[DEBUG ID-124] Respuesta RAW de Google API: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-124] [ERROR API] Google devolvió un error estructurado: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-124] [SUCCESS] API directa parseada. Encontradas: ${targetPolicies.length} políticas.`);
      } catch (e) {
        Logger.log(`[ID-124] Error crítico al ejecutar la petición directa: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-124] Detalles de las políticas objetivo: ` + 
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
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "groups_for_business.groups_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        Logger.log(`[DEBUG ID-124] Estructura completa de rootPolicy.setting: ${JSON.stringify(rootPolicy.setting)}`);
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-124] Estructura de valueNode seleccionado: ${JSON.stringify(valueNode)}`);
        
        // Verificación de owners_can_allow_external_members
        if (valueNode.owners_can_allow_external_members !== undefined) {
          extractedValue = valueNode.owners_can_allow_external_members;
        } else if (valueNode.ownersCanAllowExternalMembers !== undefined) {
          extractedValue = valueNode.ownersCanAllowExternalMembers;
        }
        
        Logger.log(`[DEBUG ID-124] Valor extraído final: ${extractedValue}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluamos la variable estricta de tipo Boolean
    if (extractedValue === false) {
      respuestaConcreta = "Privado";
      riesgo = "Bajo";
      comentario = "Se impide que los propietarios de grupos añadan miembros externos a la organización. Esto reduce drásticamente el riesgo de fuga de datos accidental o deliberada a través de listas de distribución corporativas.";
    } else if (extractedValue === true) {
      respuestaConcreta = "Publico";
      riesgo = "Alto";
      comentario = "Los propietarios de los grupos tienen permiso para añadir miembros externos. Esto expone a la organización a que terceros reciban correos electrónicos internos de distribución masiva sin supervisión del administrador.";
    } else {
      // Fallback de gobernanza: Por defecto en Google Workspace, los propietarios de grupos sí pueden añadir externos (true)
      respuestaConcreta = "";
      riesgo = "";
      comentario = "Nada detectado en los logs.";
    }

    Logger.log(`[LOG] Groups Sharing External Members Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedValue}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario124: comentario,
      riesgo124: riesgo,
      score124: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-124] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo124: "Medio", score124: 2, comentario124: msg };
  }
}
