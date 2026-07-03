/**
 * Estrategia para auditar si se permite a los propietarios de grupos agregar miembros externos.
 * Evalúa el parámetro ownersCanAllowExternalMembers.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/groups_for_business.groups_sharing
 */
class GroupsOwnersAllowExternalMembersStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-127", 
        valueKey: "valorPrincipal",
        noteKey: "comentario127",
        riskKey: "riesgo127",
        scoreKey: "score127"
      }
    ];

    super("Groups Owners Allow External Members Audit", configIDs);
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

    Logger.log(`[DEBUG ID-127] Total de políticas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes al entorno de Groups Sharing
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("groups_for_business.groups_sharing")
    );
    
    Logger.log(`[ID-127] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // LOG DE CONTROL: Si vino vacío en memoria, listamos qué hay de 'groups' disponible para diagnosticar
    if (targetPolicies.length === 0) {
      const groupsTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("groups"));
      Logger.log(`[DEBUG ID-127] [ALERT] Filtro en memoria vacío. Mapeo de tipos relacionados con 'groups' existentes: ${JSON.stringify(groupsTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-127] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*groups_for_business.groups_sharing.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-127] URL Generada para API: ${url}`);
        Logger.log(`[DEBUG ID-127] Filtro estructurado enviado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO: Imprimir exactamente lo que responde la API de Google en crudo
        Logger.log(`[DEBUG ID-127] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-127] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-127] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-127] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-127] Metadatos de políticas encontradas: ` + 
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
        Logger.log(`[DEBUG ID-127] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-127] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación resiliente de la variable estricta booleana
        if (valueNode.ownersCanAllowExternalMembers !== undefined) {
          extractedValue = valueNode.ownersCanAllowExternalMembers;
        } else if (valueNode.owners_can_allow_external_members !== undefined) {
          extractedValue = valueNode.owners_can_allow_external_members;
        }
        
        Logger.log(`[DEBUG ID-127] Valor final de la variable extraído: ${extractedValue}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluación de la variable estrictamente booleana (ownersCanAllowExternalMembers)
    if (extractedValue === true) {
      respuestaConcreta = "Activado";
      riesgo = "Alto";
      comentario = "Se permite a los propietarios de los grupos añadir miembros externos a la organización. Esto descentraliza la autoridad de federación y eleva críticamente el riesgo de fuga de información o espionaje accidental, permitiendo que usuarios locales agreguen correos de consumo personal (@gmail.com, @yahoo.com) a listas de distribución altamente sensibles.";
    } else if (extractedValue === false) {
      respuestaConcreta = "Desactivado";
      riesgo = "Bajo";
      comentario = "La capacidad de los propietarios para agregar miembros externos está bloqueada. Esto centraliza la autoridad de federación en los administradores del entorno y neutraliza el riesgo de que empleados agreguen cuentas ajenas a la organización a canales de comunicación interna.";
    } else {
      // Comportamiento por defecto seguro si la API no reporta políticas explícitas
      respuestaConcreta = "Desactivado";
      riesgo = "Bajo";
      comentario = "No se detectaron políticas explícitas en la API. El sistema aplica de forma predeterminada la política de restricción segura, bloqueando la adición de miembros externos por parte de usuarios finales.";
    }

    Logger.log(`[LOG] Groups Owners Allow External Members Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedValue}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario127: comentario,
      riesgo127: riesgo,
      score127: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-127] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo127: "Medio", score127: 2, comentario127: msg };
  }
}