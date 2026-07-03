/**
 * Estrategia para auditar el estado global de Google Takeout.
 * Evalúa el parámetro takeout_status (y variantes granulares).
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/takeout_status
 */
class GoogleTakeoutStatusStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-137", 
        valueKey: "valorPrincipal",
        noteKey: "comentario137",
        riskKey: "riesgo137",
        scoreKey: "score137"
      }
    ];

    super("Google Takeout Core Status Audit", configIDs);
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

    Logger.log(`[DEBUG ID-137] Total de políticas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes a la directiva macro de Takeout
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("takeout_status")
    );
    
    Logger.log(`[ID-137] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // LOG DE CONTROL: Si vino vacío en memoria, listamos las de servicios adicionales para diagnosticar
    if (targetPolicies.length === 0) {
      const additionalServicesTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && (t.toLowerCase().includes("takeout") || t.toLowerCase().includes("user_takeout")));
      Logger.log(`[DEBUG ID-137] [ALERT] Filtro masivo vacío. Mapeo de tipos relacionados con 'takeout' existentes: ${JSON.stringify(additionalServicesTypes)}`);
    }
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API de Google
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-137] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*takeout_status.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-137] URL Generada para API: ${url}`);
        Logger.log(`[DEBUG ID-137] Filtro estructurado enviado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente lo que responde la API de Google en crudo
        Logger.log(`[DEBUG ID-137] RESPUESTA RAW DIRECTA DE GOOGLE: ${responseText}`);

        const json = JSON.parse(responseText);
        
        if (json.error) {
          Logger.log(`[DEBUG ID-137] [ERROR API] Google denegó o falló la petición: ${JSON.stringify(json.error)}`);
        }

        targetPolicies = json.policies || [];
        Logger.log(`[ID-137] [SUCCESS] API directa parseada. Políticas recuperadas: ${targetPolicies.length}`);
      } catch (e) {
        Logger.log(`[ID-137] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-137] Metadatos de políticas encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.setting?.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedTakeoutStatus = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "takeout_status");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        
        // LOG EXPLICITO: Ver la anatomía interna del nodo de configuración
        Logger.log(`[DEBUG ID-137] Nodo rootPolicy.setting completo: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-137] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificación resiliente del parámetro takeout_status (snake_case y camelCase)
        if (valueNode.takeout_status !== undefined) {
          extractedTakeoutStatus = valueNode.takeout_status;
        } else if (valueNode.takeoutStatus !== undefined) {
          extractedTakeoutStatus = valueNode.takeoutStatus;
        }
        
        Logger.log(`[DEBUG ID-137] Valor final de la variable extraído: ${extractedTakeoutStatus}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluación estricta del Enum maestro de Google Takeout
    if (extractedTakeoutStatus === "ENABLED") {
      respuestaConcreta = "Activado";
      riesgo = "Alto";
      comentario = "La descarga masiva mediante Google Takeout está habilitada. Esto elude por completo las reglas tradicionales de Prevención de Pérdida de Datos (DLP) corporativas en tránsito y las líneas base de seguridad de CISA (GWS.COMMONCONTROLS.12.1v1), facilitando la exfiltración masiva de todos los datos de la cuenta (Drive, Gmail, Chat) hacia repositorios locales fuera del control institucional.";
    } else if (extractedTakeoutStatus === "DISABLED") {
      respuestaConcreta = "Desactivado";
      riesgo = "Bajo";
      comentario = "Google Takeout se encuentra completamente deshabilitado. Esta configuración mitiga con éxito el vector de exfiltración masiva de datos en bloque, garantizando que la información corporativa permanezca bajo la custodia, retención y auditoría estricta del inquilino.";
    } else {
      // Manejo del comportamiento por defecto (Google mantiene Takeout ENABLED de forma nativa si no hay restricción)
      respuestaConcreta = "Activado por defecto";
      riesgo = "Alto";
      comentario = "No se localizaron políticas explícitas en la API de Cloud Identity para esta unidad organizativa. Google Workspace aplica el comportamiento heredado permisivo por defecto, manteniendo la herramienta activa y dejando expuesta la superficie corporativa ante descargas locales masivas de perfiles.";
    }

    Logger.log(`[LOG] Google Takeout Core Status Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedTakeoutStatus}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario137: comentario,
      riesgo137: riesgo,
      score137: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-137] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo137: "Medio", score137: 2, comentario137: msg };
  }
}