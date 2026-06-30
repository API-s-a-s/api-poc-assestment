/**
 * Estrategia para auditar si Google Drive permite compartir SOLO con dominios en lista blanca.
 * Evalúa el mapeo de externalSharingMode a ALLOWLISTED_DOMAINS.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.external_sharing
 */
class DriveAllowlistedDomainsSharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-094", 
        valueKey: "valorPrincipal",
        noteKey: "comentario094",
        riskKey: "riesgo094",
        scoreKey: "score094"
      }
    ];

    super("Drive Allowlisted Domains Sharing Audit", configIDs);
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

    let externalSharingMode = "DISALLOWED";
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
    let riesgo094, comentario094;

    if (externalSharingMode === "ALLOWLISTED_DOMAINS") {
      respuestaConcreta = "Habilitado";
      riesgo094 = "Bajo";
      comentario094 = "El uso compartido se restringe de manera segura únicamente a dominios incluidos en la lista blanca de la organización. Esto permite la colaboración con socios de negocio específicos mientras se bloquea el intercambio con dominios y cuentas personales no autorizadas.";
    } else if (externalSharingMode === "ALLOWED") {
      respuestaConcreta = "Deshabilitado";
      riesgo094 = "Alto";
      comentario094 = "La configuración permite el uso compartido sin restricciones y no limita la compartición exclusivamente a la lista blanca de dominios. Se exponen los archivos de Drive a cualquier usuario externo a la organización.";
    } else { // DISALLOWED
      respuestaConcreta = "No Aplica (Compartir Externo Deshabilitado)";
      riesgo094 = "Bajo";
      comentario094 = "No se está utilizando una lista blanca porque el uso compartido de archivos hacia el exterior está bloqueado por completo. Es la configuración más restrictiva posible.";
    }

    Logger.log(`[LOG] Drive Allowlisted Domains Sharing Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo094}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario094: comentario094,
      riesgo094: riesgo094,
      score094: this.calcularScoreDeRiesgo(riesgo094)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo094: "Medio", score094: 2, comentario094: msg };
  }
}
