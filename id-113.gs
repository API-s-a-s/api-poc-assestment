/**
 * ID-113: Acceso Programático y Drive SDK
 * La exposición programática de los datos de la organización a aplicaciones de terceros
 * (Complementos, software SaaS de nicho, aplicaciones móviles integradas) se rige mediante el Drive SDK.
 * Ubicado bajo la configuración drive_and_docs.drive_sdk, este booleano (enable_drive_sdk_api_access en lugar de enableDriveSdkApiAccess)
 * dictamina si los usuarios pueden autorizar de forma independiente las concesiones de tokens OAuth 2.0 a los alcances de Drive.
 * 
 * Arquitectónicamente, a diferencia de la mayoría de las configuraciones de uso compartido que dependen del reductor
 * de sobrescritura rígida Max, la configuración de drive_sdk utiliza un reductor Merge. Si existen políticas conflictivas
 * aplicadas al usuario a través de diversas membresías de grupo, el sistema fusionará (merge) los atributos de más alta
 * prioridad para tomar la decisión final de autorización. Esta es una advertencia analítica vital; el script de validación
 * que consulta los resultados efectivos de la raíz comprenderá que el sistema compilará las concesiones permitidas,
 * operando consistentemente sobre valores originados en SYSTEM.
 * 
 * setting.type: settings/drive_and_docs.drive_sdk
 */
class DriveSdkApiAccessStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [{ id: "ID-113", valueKey: "valorPrincipal", noteKey: "comentario113", riskKey: "riesgo113", scoreKey: "score113" }];
    super("Drive SDK API Access Audit", configIDs);
    this.category = "Drive";
    this.customerId = customerId;
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
    const { policies, auth } = globalContext;
    if (!policies || !auth) return this._buildErrorResponse("Falta el contexto global o de autenticación.");

    // DIAGNÓSTICO TEMPORAL PARA BUSCAR EL ENDPOINT REAL
    const allTypes = policies.map(p => p.setting && p.setting.type).filter(Boolean);
    const sdkPolicies = allTypes.filter(t => t.toLowerCase().includes("sdk") || t.toLowerCase().includes("api"));
    Logger.log(`[DIAG ID-113] Políticas globales que contienen 'sdk' o 'api': ${JSON.stringify(sdkPolicies)}`);

    // Filtramos buscando el endpoint de Drive SDK. 
    let targetPolicies = policies.filter(p => p.setting && p.setting.type && p.setting.type.includes("drive_sdk"));
    Logger.log(`[ID-113] Se encontraron ${targetPolicies.length} políticas en memoria para este filtro.`);
    
    // Fallback: si no está en bulk, consultar directamente a la API
    if (targetPolicies.length === 0) {
      Logger.log(`[ID-113] [WARNING] La API masiva no trajo configuraciones para esta política. Consultando API directamente...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*drive_sdk.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" }
        };

        const response = this.fetchWithBackoff(url, options);
        const json = JSON.parse(response.getContentText());
        targetPolicies = json.policies || [];
        Logger.log(`[ID-113] [SUCCESS] API directa retornó ${targetPolicies.length} políticas.`);
      } catch (e) {
        Logger.log(`[ID-113] Error al consultar la API directamente: ${e.message}`);
        return this._buildErrorResponse(`Error al consultar la API: ${e.message}`);
      }
    }
    
    if (targetPolicies.length > 0) {
      Logger.log(`[ID-113] Detalles de las políticas encontradas: ` + JSON.stringify(targetPolicies.map(p => ({ type: p.type, name: p.name, sortOrder: p.policyQuery?.sortOrder, hasGroup: !!p.policyQuery?.group, orgUnit: p.policyQuery?.orgUnit }))));
    }
    
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
