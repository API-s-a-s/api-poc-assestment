/**
 * Estrategia para auditar la retención de historial y estado de Google Chat.
 * Evalúa los parámetros history_on_by_default y allow_user_modification.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/chat.chat_history
 */
class ChatHistorySettingsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-133", 
        valueKey: "valorPrincipal",
        noteKey: "comentario133",
        riskKey: "riesgo133",
        scoreKey: "score133"
      }
    ];

    super("Chat History and Retention Settings Audit", configIDs);
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

    Logger.log(`[DEBUG ID-133] Total de políticas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes al entorno de configuración de Chat History
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("chat.chat_history")
    );
    
    Logger.log(`[ID-133] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // LOG DE CONTROL: Si vino vacío en memoria, listamos qué hay de 'chat' disponible para diagnosticar
    if (targetPolicies.length === 0) {
      const chatTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("chat"));
      Logger.log(`[DEBUG ID-133] [ALERT] Filtro en memoria vacío. Mapeo de tipos relacionados con 'chat' existentes: ${JSON.stringify(chatTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-133] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*chat.chat_history.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-133] URL Generada para API: ${url}`);
        Logger.log(`[DEBUG ID-133] Filtro estructurado enviado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente lo que responde la API de Google en crudo
        Logger.log(`[DEBUG ID-133] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-133] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-133] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-133] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-133] Metadatos de políticas encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.setting?.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedHistoryOn = null;
    let extractedUserModification = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "chat.chat_history");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        // LOG EXPLICITO: Ver la anatomía interna del nodo de configuración
        Logger.log(`[DEBUG ID-133] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-133] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación resiliente para history_on_by_default (camelCase y snake_case)
        if (valueNode.historyOnByDefault !== undefined) {
          extractedHistoryOn = valueNode.historyOnByDefault;
        } else if (valueNode.history_on_by_default !== undefined) {
          extractedHistoryOn = valueNode.history_on_by_default;
        }

        // Verificación resiliente para allow_user_modification (camelCase y snake_case)
        if (valueNode.allowUserModification !== undefined) {
          extractedUserModification = valueNode.allowUserModification;
        } else if (valueNode.allow_user_modification !== undefined) {
          extractedUserModification = valueNode.allow_user_modification;
        }
        
        Logger.log(`[DEBUG ID-133] Valores finales extraídos -> Historial por Defecto: ${extractedHistoryOn} | Permite Modificación de Usuario: ${extractedUserModification}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluación cruzada de variables según alineación de seguridad eDiscovery y CISA
    if (extractedHistoryOn === true && extractedUserModification === false) {
      respuestaConcreta = "Historial Forzado (Activado / No modificable)";
      riesgo = "Bajo";
      comentario = "El historial de chat está configurado de forma segura: activo por defecto y sin permisos de modificación para el usuario. Cumple con los estándares de retención de datos para eDiscovery e impide que un atacante borre la evidencia forense tras un incidente de exfiltración o phishing.";
    } else if (extractedHistoryOn === true && extractedUserModification === true) {
      respuestaConcreta = "Historial Activo (Modificable por el usuario)";
      riesgo = "Medio";
      comentario = "El historial está encendido inicialmente, pero se permite que los usuarios lo apaguen de forma discrecional. Esto debilita la postura probatoria del dominio, permitiendo que hilos de conversación altamente sensibles sean eliminados u ocultados voluntariamente.";
    } else if (extractedHistoryOn === false) {
      respuestaConcreta = extractedUserModification ? "Historial Apagado (Modificable)" : "Historial Apagado Forzado";
      riesgo = "Alto";
      comentario = "El historial de las conversaciones se encuentra desactivado por defecto. Esta configuración destruye las capacidades de eDiscovery y auditoría en tiempo real del inquilino, facilitando ataques internos efímeros sin dejar registro de actividad en la plataforma.";
    } else {
      // Manejo de valores por defecto seguros de Google
      respuestaConcreta = "Revisión manual / Por defecto";
      riesgo = "Medio";
      comentario = "No se detectaron directivas explícitas de Cloud Identity para la retención histórica del chat. Se recomienda revisar manualmente la consola en Google Chat > Configuración de Chat para verificar que las directivas heredadas cumplan con el marco probatorio organizacional.";
    }

    Logger.log(`[LOG] Chat History and Retention Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | HistoryOn: ${extractedHistoryOn} | UserMod: ${extractedUserModification}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario133: comentario,
      riesgo133: riesgo,
      score133: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-133] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo133: "Medio", score133: 2, comentario133: msg };
  }
}