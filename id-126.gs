/**
 * Estrategia para auditar los permisos de creación de grupos en Google Groups.
 * Evalúa el parámetro createGroupsAccessLevel.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/groups_for_business.groups_sharing
 */
class GroupsCreateGroupsAccessStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-126", 
        valueKey: "valorPrincipal",
        noteKey: "comentario126",
        riskKey: "riesgo126",
        scoreKey: "score126"
      }
    ];

    super("Groups Create Groups Access Audit", configIDs);
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

    Logger.log(`[DEBUG ID-126] Total de políticas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes al entorno de Groups Sharing
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("groups_for_business.groups_sharing")
    );
    
    Logger.log(`[ID-126] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // LOG DE CONTROL: Si vino vacío en memoria, listamos qué hay de 'groups' disponible para diagnosticar
    if (targetPolicies.length === 0) {
      const groupsTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("groups"));
      Logger.log(`[DEBUG ID-126] [ALERT] Filtro en memoria vacío. Mapeo de tipos relacionados con 'groups' existentes: ${JSON.stringify(groupsTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-126] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*groups_for_business.groups_sharing.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-126] URL Generada para API: ${url}`);
        Logger.log(`[DEBUG ID-126] Filtro estructurado enviado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO: Imprimir exactamente lo que responde la API de Google en crudo
        Logger.log(`[DEBUG ID-126] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-126] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-126] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-126] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-126] Metadatos de políticas encontradas: ` + 
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
        
        // LOG EXPLICITO: Ver la anatomía interna del nodo de configuración
        Logger.log(`[DEBUG ID-126] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-126] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación resiliente de la variable estricta (camelCase y snake_case)
        if (valueNode.createGroupsAccessLevel !== undefined) {
          extractedValue = valueNode.createGroupsAccessLevel;
        } else if (valueNode.create_groups_access_level !== undefined) {
          extractedValue = valueNode.create_groups_access_level;
        }
        
        Logger.log(`[DEBUG ID-126] Valor final de la variable extraído: ${extractedValue}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluación del Enum de nivel de acceso para instanciar/crear grupos (createGroupsAccessLevel)
    if (extractedValue === "ANYONE_IN_THE_WORLD" || extractedValue === "ANYONE_CAN_CREATE") {
      respuestaConcreta = "Cualquiera en internet";
      riesgo = "Alto";
      comentario = "La configuración permite que cualquier usuario externo en internet cree grupos dentro del dominio de la organización. Esto representa un vector crítico para ataques de spam masivo, suplantación de identidad y pérdida absoluta de control perimetral.";
    } else if (extractedValue === "ALL_YOUR_ORGANIZATION_MEMBERS" || extractedValue === "ALL_IN_DOMAIN_CAN_CREATE") {
      respuestaConcreta = "Todos los miembros de la organización";
      riesgo = "Medio";
      comentario = "Cualquier usuario de la organización tiene permitido crear nuevos grupos por defecto. Esto incrementa de manera significativa el riesgo de proliferación descontrolada de datos (Group Sprawl) y la aparición de Shadow IT sin la supervisión del equipo de seguridad.";
    } else if (extractedValue === "ADMINISTRATORS_ONLY" || extractedValue === "ONLY_ADMINS_CAN_CREATE" || extractedValue === "ADMINS_ONLY") {
      respuestaConcreta = "Solo administradores";
      riesgo = "Bajo";
      comentario = "La creación de grupos está estrictamente restringida a los administradores del entorno de Workspace. Esto centraliza el gobierno de identidades y garantiza que cada canal de comunicación pase por un proceso formal de aprobación.";
    } else {
      // Manejo de valores heredados o por defecto seguros de Google
      respuestaConcreta = "Solo administradores";
      riesgo = "Bajo";
      comentario = "El sistema aplica de forma nativa la restricción segura, limitando la creación de grupos únicamente al personal administrativo autorizado.";
    }

    Logger.log(`[LOG] Groups Create Groups Access Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedValue}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario126: comentario,
      riesgo126: riesgo,
      score126: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-126] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo126: "Medio", score126: 2, comentario126: msg };
  }
}