/**
 * Estrategia para auditar las opciones para compartir archivos de Google Drive externamente.
 * Evalúa si se permite compartir con cualquiera fuera de la organización (externalSharingMode).
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.external_sharing
 */
class DriveExternalSharingModeStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-093", 
        valueKey: "valorPrincipal",
        noteKey: "comentario093",
        riskKey: "riesgo093",
        scoreKey: "score093"
      }
    ];

    super("Drive External Sharing Mode Audit", configIDs);
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

    let externalSharingMode = "DISALLOWED"; // Por defecto, asumimos cerrado si no hay políticas
    let rawData = null;

    if (sharingPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(sharingPolicies, "drive_and_docs.external_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Campo en camelCase según la API real
        if (valueNode.externalSharingMode) {
          externalSharingMode = valueNode.externalSharingMode;
        }
      }
    }

    let respuestaConcreta;
    let riesgo093, comentario093;

    if (externalSharingMode === "ALLOWED") {
      respuestaConcreta = "Habilitado";
      riesgo093 = "Alto";
      comentario093 = "La configuración permite a los usuarios compartir archivos de Drive con cualquier persona fuera de la organización. Esto expone un riesgo significativo de exfiltración de datos, ya que archivos confidenciales pueden compartirse con cuentas externas no verificadas.";
    } else if (externalSharingMode === "ALLOWLISTED_DOMAINS") {
      respuestaConcreta = "Habilitado (Solo dominios permitidos)";
      riesgo093 = "Medio";
      comentario093 = "La configuración permite compartir archivos externamente, pero está limitada a una lista blanca de dominios específicos aprobados por el administrador. Esto reduce el riesgo de exposición a terceros no autorizados, aunque requiere constante mantenimiento de la lista blanca.";
    } else { // DISALLOWED u otros no definidos abiertamente
      respuestaConcreta = "Deshabilitado";
      riesgo093 = "Bajo";
      comentario093 = "El uso compartido externo de archivos de Drive se encuentra deshabilitado de forma generalizada en la OU raíz. Esto mitiga efectivamente el riesgo de exposición de información hacia entidades ajenas a la organización.";
    }

    Logger.log(`[LOG] Drive External Sharing Mode Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo093}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario093: comentario093,
      riesgo093: riesgo093,
      score093: this.calcularScoreDeRiesgo(riesgo093)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo093: "Medio", score093: 2, comentario093: msg };
  }
}
