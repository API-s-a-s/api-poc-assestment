/**
 * Estrategia para auditar el uso compartido de archivos externos en Google Chat.
 * Evalúa el parámetro external_file_sharing.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/chat.chat_file_sharing
 */
class ChatFileSharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-136", 
        valueKey: "valorPrincipal",
        noteKey: "comentario136",
        riskKey: "riesgo136",
        scoreKey: "score136"
      }
    ];

    super("Chat External File Sharing Audit", configIDs);
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

    Logger.log(`[DEBUG ID-136] Total de políticas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes al intercambio de archivos de Chat
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("chat.chat_file_sharing")
    );
    
    Logger.log(`[ID-136] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // LOG DE CONTROL: Si vino vacío en memoria, listamos qué hay de 'chat' disponible para diagnosticar
    if (targetPolicies.length === 0) {
      const chatTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("chat"));
      Logger.log(`[DEBUG ID-136] [ALERT] Filtro en memoria vacío. Mapeo de tipos relacionados con 'chat' existentes: ${JSON.stringify(chatTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-136] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*chat.chat_file_sharing.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-136] URL Generada para API: ${url}`);
        Logger.log(`[DEBUG ID-136] Filtro estructurado enviado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente lo que responde la API de Google en crudo
        Logger.log(`[DEBUG ID-136] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-136] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-136] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-136] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-136] Metadatos de políticas encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.setting?.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedFileSharing = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "chat.chat_file_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        // LOG EXPLICITO: Ver la anatomía interna del nodo de configuración
        Logger.log(`[DEBUG ID-136] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-136] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación resiliente del parámetro external_file_sharing (snake_case y camelCase)
        if (valueNode.external_file_sharing !== undefined) {
          extractedFileSharing = valueNode.external_file_sharing;
        } else if (valueNode.externalFileSharing !== undefined) {
          extractedFileSharing = valueNode.externalFileSharing;
        }
        
        Logger.log(`[DEBUG ID-136] Valor final de la variable extraído: ${extractedFileSharing}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluación estricta del Enum de external_file_sharing
    if (extractedFileSharing === "ALL_FILES") {
      respuestaConcreta = "Permitir todos los archivos";
      riesgo = "Alto";
      comentario = "Se permite el intercambio irrestricto de todo tipo de archivos con usuarios externos a través de Google Chat.";
    } else if (extractedFileSharing === "IMAGES_ONLY") {
      respuestaConcreta = "Solo imágenes";
      riesgo = "Medio";
      comentario = "Se restringe el uso compartido externo exclusivamente a archivos de imagen.";
    } else if (extractedFileSharing === "NO_FILES") {
      respuestaConcreta = "Bloquear todos los archivos";
      riesgo = "Bajo";
      comentario = "El intercambio externo de cualquier tipo de archivo a través de la plataforma de chat está completamente deshabilitado.";
    } else if (extractedFileSharing === "FILE_SHARING_OPTION_UNSPECIFIED") {
      respuestaConcreta = "No especificado";
      riesgo = "Medio";
      comentario = "La directiva de compartición de archivos externos no está configurada de manera explícita en esta OU. Se recomienda forzar un estado restrictivo.";
    } else {
      // Manejo seguro para políticas ausentes
      respuestaConcreta = "Bloquear todos los archivos por defecto";
      riesgo = "Bajo";
      comentario = "No se detectaron políticas explícitas en la consola de admin.";
    }

    Logger.log(`[LOG] Chat External File Sharing Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedFileSharing}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario136: comentario,
      riesgo136: riesgo,
      score136: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-136] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo136: "Medio", score136: 2, comentario136: msg };
  }
}