/**
 * Estrategia para auditar las políticas de la organización para compartir en Google Data Studio (Looker).
 * Evalúa el parámetro de estado booleano is_enabled para el servicio de datos.
 * Utiliza Cloud Identity Policy API (v1).
 * Ubicación en Consola: Additional Google services
 * Scope: Domain
 */
class LookerDataStudioSharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-138", 
        valueKey: "valorPrincipal",
        noteKey: "comentario138",
        riskKey: "riesgo138",
        scoreKey: "score138"
      }
    ];

    super("Looker Data Studio Organization Sharing Policies Audit", configIDs);
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

    Logger.log(`[DEBUG ID-138] Total de políticas recibidas en contexto global: ${policies.length}`);

    // Filtramos las políticas según el controlador service_status y nombre de servicio data_studio
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").toLowerCase().includes("data_studio") && (p.setting.type || "").endsWith("service_status")
    );
    
    Logger.log(`[ID-138] Se encontraron ${targetPolicies.length} políticas en memoria para este filtro.`);
    
    // LOG DE CONTROL: Si viene vacío en memoria, listamos los tipos service_status existentes para diagnóstico
    if (targetPolicies.length === 0) {
      const serviceStatusTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("service_status"));
      Logger.log(`[DEBUG ID-138] [ALERT] Filtro masivo vacío. Mapeo de tipos relacionados con 'service_status' en memoria: ${JSON.stringify(serviceStatusTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-138] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*data_studio.*service_status.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-138] URL de consulta directa generada: ${url}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente qué es lo que llega de la API de Google
        Logger.log(`[DEBUG ID-138] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-138] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-138] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-138] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-138] Metadatos de políticas de Data Studio encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.setting?.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedIsEnabled = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "service_status");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        // LOG EXPLICITO: Ver la anatomía interna del nodo de configuración
        Logger.log(`[DEBUG ID-138] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-138] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación de la variable de estado booleana (is_enabled / isEnabled / serviceState)
        if (valueNode.is_enabled !== undefined) {
          extractedIsEnabled = valueNode.is_enabled;
        } else if (valueNode.isEnabled !== undefined) {
          extractedIsEnabled = valueNode.isEnabled;
        } else if (valueNode.serviceState !== undefined) {
          extractedIsEnabled = valueNode.serviceState === "ENABLED";
        } else if (valueNode.service_state !== undefined) {
          extractedIsEnabled = valueNode.service_state === "ENABLED";
        }
        
        Logger.log(`[DEBUG ID-138] Valor de estado extraído final: ${extractedIsEnabled}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluación del estado booleano de la aplicación (is_enabled) a nivel de Dominio
    if (extractedIsEnabled === true) {
      respuestaConcreta = "Activado";
      riesgo = "Alto";
      comentario = "El servicio de Google Data Studio se encuentra activo a nivel de dominio.";
    } else if (extractedIsEnabled === false) {
      respuestaConcreta = "Desactivado";
      riesgo = "Bajo";
      comentario = "El servicio de Google Data Studio está completamente deshabilitado a nivel de dominio.";
    } else {
      // Comportamiento por defecto seguro o heredado si la API no reporta políticas explícitas
      respuestaConcreta = "Activado por defecto";
      riesgo = "Alto";
      comentario = "No se detectaron políticas explícitas en la consola de admin.";
    }

    Logger.log(`[LOG] Looker Data Studio Service Status Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedIsEnabled}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario138: comentario,
      riesgo138: riesgo,
      score138: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-138] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo138: "Medio", score138: 2, comentario138: msg };
  }
}