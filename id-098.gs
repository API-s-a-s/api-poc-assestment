/**
 * Estrategia para auditar si se permite a los usuarios recibir archivos de fuera del dominio.
 * Evalúa la propiedad booleana allowReceivingExternalFiles.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.external_sharing
 */
class DriveAllowReceivingExternalFilesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-098", 
        valueKey: "valorPrincipal",
        noteKey: "comentario098",
        riskKey: "riesgo098",
        scoreKey: "score098"
      }
    ];

    super("Drive Allow Receiving External Files Audit", configIDs);
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

    let allowReceiving = false;
    let rawData = null;

    if (sharingPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(sharingPolicies, "drive_and_docs.external_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Campo en camelCase según la API real
        if (valueNode.allowReceivingExternalFiles === true) {
          allowReceiving = true;
        }
      }
    }

    let respuestaConcreta;
    let riesgo098, comentario098;

    if (allowReceiving) {
      respuestaConcreta = "Habilitado";
      riesgo098 = "Medio";
      comentario098 = "Los usuarios del dominio pueden recibir archivos compartidos desde cuentas externas (personales y corporativas ajenas). Aunque facilita la colaboración, abre un vector de ingreso de contenido malicioso o no autorizado proveniente de cuentas no gestionadas por la organización.";
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo098 = "Bajo";
      comentario098 = "Los usuarios no pueden recibir archivos compartidos desde fuera del dominio. Esto mitiga el riesgo de ingreso de contenido malicioso, phishing a través de archivos compartidos y la recepción de datos sensibles no autorizados desde terceros.";
    }

    Logger.log(`[LOG] Drive Allow Receiving External Files Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo098}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario098: comentario098,
      riesgo098: riesgo098,
      score098: this.calcularScoreDeRiesgo(riesgo098)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo098: "Medio", score098: 2, comentario098: msg };
  }
}
