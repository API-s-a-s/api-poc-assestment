/**
 * Estrategia para auditar la separación de datos en iOS (Apps administradas).
 * ID-156: Permitir abrir documentos en aplicaciones administradas.
 * Utiliza Cloud Identity Policy API (evaluada en memoria) para leer la configuración 
 * de settings/drive_and_docs.external_sharing en la OU raíz.
 */
class ManagedAppsDataSharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-156", 
        valueKey: "valorPrincipal",
        noteKey: "comentario156",
        riskKey: "riesgo156",
        scoreKey: "score156"
      }
    ];
    super("Managed Apps Data Sharing Audit (ID-156)", configIDs);
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

    Logger.log("========== INICIO DIAGNÓSTICO ID-156 (MANAGED APPS DATA SHARING) ==========");

    let externalSharingMode = "UNKNOWN";
    let policyFound = false;

    try {
      Logger.log(`[ID-156 DEBUG] Total de políticas en globalContext: ${policies.length}`);
      
      const sharingPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("drive_and_docs.external_sharing"));
      
      // Utilizamos el Reducer para obtener la política efectiva en la raíz
      const sharingPolicy = PolicyReducerFactory.getEffectiveRootPolicy(sharingPolicies, "drive_and_docs.external_sharing");
      
      if (sharingPolicy) {
        Logger.log(`[ID-156 DEBUG] Objeto completo devuelto por el Reducer: ${JSON.stringify(sharingPolicy)}`);
      }
      
      if (sharingPolicy && sharingPolicy.setting) {
        policyFound = true;
        
        let valueNode = sharingPolicy.setting.value || sharingPolicy.setting;
        
        // Extraemos la variable
        externalSharingMode = valueNode.externalSharingMode || "UNSPECIFIED";
        
        Logger.log(`[ID-156] Política de compartición encontrada. externalSharingMode: ${externalSharingMode}`);
        Logger.log(`[ID-156 RAW LOG] Nodo de valor extraído: ${JSON.stringify(valueNode)}`);
      } else {
        Logger.log("[ID-156] No se encontró política explícita para settings/drive_and_docs.external_sharing en la raíz.");
      }
    } catch (e) {
      Logger.log(`[ID-156] Excepción capturada al evaluar políticas: ${e.message}`);
      return this._buildErrorResponse(`Error al procesar la política de compartición: ${e.message}`);
    }

    Logger.log("========== FIN DIAGNÓSTICO ID-156 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo156 = "Bajo";
    let comentario156 = "";
    
    let valorPrincipal = externalSharingMode;

    if (externalSharingMode === "ALLOWED") {
      valorPrincipal = "Permitido"
      riesgo156 = "Alto";
      comentario156 = "El modo de compartición externa es 'ALLOWED'. Los documentos corporativos pueden ser abiertos tanto en aplicaciones administradas como personales.";
    } else {
      riesgo156 = "Bajo";
      comentario156 = `Intercambio administrado activo (${externalSharingMode}). Las políticas están utilizando las restricciones nativas del sistema operativo para asegurar que el contenido corporativo descargado solo pueda abrirse en otras aplicaciones aprobadas y gestionadas por la empresa.`;
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario156: comentario156,
      riesgo156: riesgo156,
      score156: this.calcularScoreDeRiesgo(riesgo156)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-156] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo156: "Medio",
      score156: 2,
      comentario156: msg
    };
  }
}