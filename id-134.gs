/**
 * Estrategia para auditar las advertencias visuales al chatear con usuarios externos en Google Chat.
 * Evalúa múltiples variables combinadas como allowExternalChat, warnExternalChat y showExternalPresence.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/chat.external_chat_restriction
 */
class ChatExternalWarningStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-134", 
        valueKey: "valorPrincipal",
        noteKey: "comentario134",
        riskKey: "riesgo134",
        scoreKey: "score134"
      }
    ];

    super("Chat External Interaction Warnings Audit", configIDs);
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

    Logger.log(`[DEBUG ID-134] Total de políticas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes a las restricciones externas de Chat
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("chat.external_chat_restriction")
    );
    
    Logger.log(`[ID-134] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // LOG DE CONTROL: Si vino vacío en memoria, listamos qué hay de 'chat' disponible para diagnosticar
    if (targetPolicies.length === 0) {
      const chatTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("chat"));
      Logger.log(`[DEBUG ID-134] [ALERT] Filtro en memoria vacío. Mapeo de tipos relacionados con 'chat' existentes: ${JSON.stringify(chatTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-134] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*chat.external_chat_restriction.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-134] URL Generada para API: ${url}`);
        Logger.log(`[DEBUG ID-134] Filtro estructurado enviado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente lo que responde la API de Google en crudo
        Logger.log(`[DEBUG ID-134] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-134] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-134] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-134] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-134] Metadatos de políticas encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.setting?.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedAllowExternal = null;
    let extractedWarnExternal = null;
    let extractedShowPresence = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "chat.external_chat_restriction");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        // LOG EXPLICITO: Ver la anatomía interna del nodo de configuración de Chat
        Logger.log(`[DEBUG ID-134] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-134] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación de allowExternalChat
        if (valueNode.allowExternalChat !== undefined) extractedAllowExternal = valueNode.allowExternalChat;
        else if (valueNode.allow_external_chat !== undefined) extractedAllowExternal = valueNode.allow_external_chat;

        // Verificación de warnExternalChat
        if (valueNode.warnExternalChat !== undefined) extractedWarnExternal = valueNode.warnExternalChat;
        else if (valueNode.warn_external_chat !== undefined) extractedWarnExternal = valueNode.warn_external_chat;

        // Verificación de showExternalPresence
        if (valueNode.showExternalPresence !== undefined) extractedShowPresence = valueNode.showExternalPresence;
        else if (valueNode.show_external_presence !== undefined) extractedShowPresence = valueNode.show_external_presence;
        
        Logger.log(`[DEBUG ID-134] Valores finales -> AllowExternal: ${extractedAllowExternal} | WarnExternal: ${extractedWarnExternal} | ShowPresence: ${extractedShowPresence}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Lógica matricial combinada basada en la disponibilidad del Chat Externo y las Alertas
    if (extractedAllowExternal === false) {
      respuestaConcreta = "Chat externo bloqueado de raíz";
      riesgo = "Bajo";
      comentario = "La comunicación con usuarios externos está completamente deshabilitada en esta OU. Al no existir transferencia perimetral de mensajes, las alertas visuales se vuelven redundantes y el vector de Spear Phishing por chat queda neutralizado.";
    } else if (extractedAllowExternal === true || extractedAllowExternal === null) {
      // Si el chat externo está permitido, evaluamos obligatoriamente las advertencias visuales
      if (extractedWarnExternal === false) {
        respuestaConcreta = "Chat externo activo (Sin advertencias visuales)";
        riesgo = "Alto";
        comentario = "Se permite la comunicación con usuarios externos, pero se han desactivado las advertencias visuales y banners en la interfaz. Esto incrementa críticamente el riesgo de fraude de suplantación ejecutiva (CEO Fraud), dado que los empleados no recibirán alertas proactivas si interactúan con una identidad externa maliciosa utilizando el mismo nombre de un directivo interno.";
      } else {
        // Escenario seguro alternativo: Chat permitido pero con alertas de control compensatorio activadas
        respuestaConcreta = "Chat externo activo con advertencias visuales";
        riesgo = "Bajo";
        comentario = "El chat con dominios externos está permitido debido a requerimientos comerciales, pero se aplican controles compensatorios estrictos. La interfaz de usuario emitirá alertas visuales y banners explícitos al iniciar hilos con personas ajenas a la organización, mitigando ataques de ingeniería social.";
      }
    } else {
      // Comportamiento seguro por defecto de Google Workspace
      respuestaConcreta = "Advertencias activas (Valor por defecto)";
      riesgo = "Bajo";
      comentario = "No se localizaron políticas explícitas en la API de Cloud Identity. El sistema aplica de forma nativa la configuración recomendada de Google Workspace, manteniendo activos los indicadores de presencia externa y banners de advertencia para proteger la identidad institucional.";
    }

    Logger.log(`[LOG] Chat External Interaction Warnings Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Allow: ${extractedAllowExternal} | Warn: ${extractedWarnExternal}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario134: comentario,
      riesgo134: riesgo,
      score134: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-134] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo134: "Medio", score134: 2, comentario134: msg };
  }
}