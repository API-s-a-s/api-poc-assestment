/**
 * Estrategia para auditar si se permite acceder a Google Drive con la API de Drive SDK.
 * Evalúa enable_drive_sdk_api_access.
 * setting.type: settings/drive_and_docs.drive_sdk (o similar, se infiere con "drive_sdk")
 */
class DriveSdkApiAccessStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [{ id: "ID-113", valueKey: "valorPrincipal", noteKey: "comentario113", riskKey: "riesgo113", scoreKey: "score113" }];
    super("Drive SDK API Access Audit", configIDs);
    this.category = "Drive";
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    // DIAGNÓSTICO TEMPORAL PARA BUSCAR EL ENDPOINT REAL
    const allTypes = policies.map(p => p.setting && p.setting.type).filter(Boolean);
    const sdkPolicies = allTypes.filter(t => t.toLowerCase().includes("sdk") || t.toLowerCase().includes("api"));
    Logger.log(`[DIAG ID-113] Políticas globales que contienen 'sdk' o 'api': ${JSON.stringify(sdkPolicies)}`);

    // Filtramos buscando el endpoint de Drive SDK. 
    const targetPolicies = policies.filter(p => p.setting && p.setting.type && p.setting.type.includes("drive_sdk"));
    
    let extractedValue = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      // Intentamos usar el Reducer asumiendo que el tipo es de merge o max
      const settingType = targetPolicies[0].setting.type; 
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, settingType);
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Uso de snake_case según CSV, o camelCase de la API
        if (valueNode.enable_drive_sdk_api_access !== undefined) {
            extractedValue = valueNode.enable_drive_sdk_api_access;
        } else if (valueNode.enableDriveSdkApiAccess !== undefined) {
            extractedValue = valueNode.enableDriveSdkApiAccess;
        }
      }
    }

    let respuestaConcreta, riesgo, comentario;

    if (extractedValue === true) {
      respuestaConcreta = "Habilitado";
      riesgo = "Alto";
      comentario = "Se permite el acceso a Google Drive mediante la API de Drive SDK. Aplicaciones de terceros pueden solicitar acceso programático a los archivos de los usuarios, incrementando la superficie de ataque para exfiltración si no hay estrictos controles OAuth.";
    } else if (extractedValue === false) {
      respuestaConcreta = "Deshabilitado";
      riesgo = "Bajo";
      comentario = "El acceso a través de la API de Drive SDK está bloqueado. Las aplicaciones externas de terceros no pueden acceder a los archivos de Drive mediante el SDK, ofreciendo máxima protección de los datos corporativos.";
    } else {
      respuestaConcreta = "No definido (Requiere Revisión)";
      riesgo = "Medio";
      comentario = "No se encontró configuración explícita para Drive SDK en las políticas. Se recomienda revisar la consola de administración en Drive y Documentos > Funciones y Aplicaciones > Drive SDK.";
    }

    Logger.log(`[LOG] Drive SDK API Access Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    return { 
      name: this.name, 
      raw: rawData, 
      valorPrincipal: respuestaConcreta, 
      comentario113: comentario, 
      riesgo113: riesgo, 
      score113: this.calcularScoreDeRiesgo(riesgo) 
    };
  }

  _buildErrorResponse(msg) { 
    return { name: this.name, valorPrincipal: "ERROR", riesgo113: "Medio", score113: 2, comentario113: msg }; 
  }
}
