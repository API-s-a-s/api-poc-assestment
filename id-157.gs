/**
 * Estrategia para auditar la separación de datos en iOS (Apps no administradas).
 * ID-157: Permitir abrir documentos en aplicaciones no administradas.
 * Utiliza Cloud Identity Policy API (evaluada en memoria) para leer la configuración 
 * de settings/drive_and_docs.external_sharing en la OU raíz.
 */
class UnmanagedAppsDataSharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-157", 
        valueKey: "valorPrincipal",
        noteKey: "comentario157",
        riskKey: "riesgo157",
        scoreKey: "score157"
      }
    ];
    super("Unmanaged Apps Data Sharing Audit (ID-157)", configIDs);
    this.customerId = customerId;
    this.category = "Gestión de dispositivos"; // Categoría solicitada
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
    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global (políticas no encontradas en memoria).");
    }

    Logger.log("========== INICIO DIAGNÓSTICO ID-157 (UNMANAGED APPS DATA SHARING) ==========");

    let externalSharingMode = "UNKNOWN";
    let policyFound = false;

    try {
      Logger.log(`[ID-157 DEBUG] Total de políticas en globalContext: ${policies.length}`);
      
      const sharingPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("drive_and_docs.external_sharing"));
      
      // Utilizamos el Reducer para obtener la política efectiva en la raíz para este setting
      const sharingPolicy = PolicyReducerFactory.getEffectiveRootPolicy(sharingPolicies, "drive_and_docs.external_sharing");
      
      if (sharingPolicy) {
        Logger.log(`[ID-157 DEBUG] Objeto completo devuelto por el Reducer: ${JSON.stringify(sharingPolicy)}`);
      }
      
      if (sharingPolicy && sharingPolicy.setting) {
        policyFound = true;
        
        let valueNode = sharingPolicy.setting.value || sharingPolicy.setting;
        
        // Extraemos la variable exacta validada en los logs
        externalSharingMode = valueNode.externalSharingMode || "UNSPECIFIED";
        
        Logger.log(`[ID-157] Política de compartición encontrada. externalSharingMode: ${externalSharingMode}`);
        Logger.log(`[ID-157 RAW LOG] Nodo de valor extraído: ${JSON.stringify(valueNode)}`);
      } else {
        Logger.log("[ID-157] No se encontró política explícita para settings/drive_and_docs.external_sharing en la raíz.");
      }
    } catch (e) {
      Logger.log(`[ID-157] Excepción capturada al evaluar políticas: ${e.message}`);
      return this._buildErrorResponse(`Error al procesar la política de compartición: ${e.message}`);
    }

    Logger.log("========== FIN DIAGNÓSTICO ID-157 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo157 = "Bajo";
    let comentario157 = "";
    
    let valorPrincipal = externalSharingMode;

    if (externalSharingMode === "ALLOWED") {
      riesgo157 = "Alto";
      comentario157 = "El intercambio de datos está configurado como 'ALLOWED'. Esto permite que los datos corporativos fluyan hacia el espacio personal del usuario, lo que representa un riesgo crítico de fuga o exfiltración de información institucional.";
    } else {
      riesgo157 = "Bajo";
      comentario157 = `El intercambio de datos se encuentra restringido (${externalSharingMode}). Las restricciones nativas aseguran que el contenido descargado solo pueda abrirse en otras aplicaciones aprobadas por la empresa.`;
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario157: comentario157,
      riesgo157: riesgo157,
      score157: this.calcularScoreDeRiesgo(riesgo157)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-157] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo157: "Medio",
      score157: 2,
      comentario157: msg
    };
  }
}