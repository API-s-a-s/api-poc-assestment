/**
 * Estrategia para auditar si se permiten chats externos en el dominio/OU (Hard Block).
 * Evalúa el parámetro allowExternalChat.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/chat.external_chat_restriction
 */
class ChatAllowExternalChatsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-135", 
        valueKey: "valorPrincipal",
        noteKey: "comentario135",
        riskKey: "riesgo135",
        scoreKey: "score135"
      }
    ];

    super("Chat Allow External Chats Audit", configIDs);
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

    Logger.log(`[DEBUG ID-135] Total de políticas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes a las restricciones externas de Chat
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("chat.external_chat_restriction")
    );
    
    Logger.log(`[ID-135] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // LOG DE CONTROL: Si vino vacío en memoria, listamos qué hay de 'chat' disponible para diagnosticar
    if (targetPolicies.length === 0) {
      const chatTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("chat"));
      Logger.log(`[DEBUG ID-135] [ALERT] Filtro en memoria vacío. Mapeo de tipos relacionados con 'chat' existentes: ${JSON.stringify(chatTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-135] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*chat.external_chat_restriction.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-135] URL Generada para API: ${url}`);
        Logger.log(`[DEBUG ID-135] Filtro estructurado enviado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente lo que responde la API de Google en crudo
        Logger.log(`[DEBUG ID-135] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-135] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-135] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-135] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-135] Metadatos de políticas encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.setting?.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedAllowExternal = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "chat.external_chat_restriction");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        // LOG EXPLICITO: Ver la anatomía interna del nodo de configuración de Chat
        Logger.log(`[DEBUG ID-135] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-135] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación resiliente de allowExternalChat (camelCase y snake_case)
        if (valueNode.allowExternalChat !== undefined) {
          extractedAllowExternal = valueNode.allowExternalChat;
        } else if (valueNode.allow_external_chat !== undefined) {
          extractedAllowExternal = valueNode.allow_external_chat;
        }
        
        Logger.log(`[DEBUG ID-135] Valor final extraído -> AllowExternalChat: ${extractedAllowExternal}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluación estricta del interruptor maestro perimetral
    if (extractedAllowExternal === false) {
      respuestaConcreta = "Deshabilitado";
      riesgo = "Bajo";
      comentario = "Los chats con usuarios externos a la organización están completamente deshabilitados.";
    } else if (extractedAllowExternal === true) {
      respuestaConcreta = "Habilitado";
      riesgo = "Alto";
      comentario = "Se permite a los usuarios iniciar y recibir chats con cuentas externas al dominio de confianza.";
    } else {
      // Comportamiento predeterminado permisivo si la API viene vacía
      respuestaConcreta = "Habilitado por defecto";
      riesgo = "Alto";
      comentario = "El sistema hereda el comportamiento nativo permisivo de Google Workspace, permitiendo interacciones de chat externo sin un bloqueo duro perimetral.";
    }

    Logger.log(`[LOG] Chat Allow External Chats Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedAllowExternal}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario135: comentario,
      riesgo135: riesgo,
      score135: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-135] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo135: "Medio", score135: 2, comentario135: msg };
  }
}