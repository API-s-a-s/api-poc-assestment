/**
 * Estrategia para auditar las advertencias al compartir con usuarios externos a la organización.
 * Evalúa la propiedad booleana warnForExternalSharing.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.external_sharing
 */
class DriveWarnExternalSharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-095", 
        valueKey: "valorPrincipal",
        noteKey: "comentario095",
        riskKey: "riesgo095",
        scoreKey: "score095"
      }
    ];

    super("Drive Warn External Sharing Audit", configIDs);
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

    // Filtro específico: solo la política de external_sharing de Drive
    const sharingPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("drive_and_docs.external_sharing"));

    let warnEnabled = false;
    let isSharingDisallowed = false;
    let rawData = null;

    if (sharingPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(sharingPolicies, "drive_and_docs.external_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Campos en camelCase según la API real
        if (valueNode.externalSharingMode === "DISALLOWED") {
          isSharingDisallowed = true;
        }

        if (valueNode.warnForExternalSharing === true) {
          warnEnabled = true;
        }
      }
    }

    let respuestaConcreta;
    let riesgo095, comentario095;

    if (isSharingDisallowed) {
      respuestaConcreta = "No Aplica";
      riesgo095 = "Bajo";
      comentario095 = "El uso compartido externo está completamente deshabilitado, por lo que la advertencia no entra en vigor. La postura de seguridad es óptima.";
    } else if (warnEnabled) {
      respuestaConcreta = "Habilitado";
      riesgo095 = "Bajo";
      comentario095 = "La advertencia para compartir externamente está habilitada. Los usuarios reciben un aviso visible antes de compartir un documento con usuarios externos, lo que reduce el riesgo de exposición accidental de información corporativa a personas ajenas.";
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo095 = "Medio";
      comentario095 = "La advertencia está deshabilitada. Los usuarios no recibirán ninguna notificación de precaución al compartir datos fuera del dominio corporativo, aumentando la probabilidad de filtración de datos de manera no intencionada.";
    }

    Logger.log(`[LOG] Drive Warn External Sharing Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo095}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario095: comentario095,
      riesgo095: riesgo095,
      score095: this.calcularScoreDeRiesgo(riesgo095)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo095: "Medio", score095: 2, comentario095: msg };
  }
}
