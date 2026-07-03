/**
 * Estrategia para auditar si se permite compartir con personas sin cuenta de Google.
 * Evalúa la propiedad booleana allow_non_google_invites.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.external_sharing
 */
class DriveAllowNonGoogleInvitesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-096", 
        valueKey: "valorPrincipal",
        noteKey: "comentario096",
        riskKey: "riesgo096",
        scoreKey: "score096"
      }
    ];

    super("Drive Allow Non-Google Invites Audit", configIDs);
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
    Logger.log(`[ID-096] Se encontraron ${sharingPolicies.length} políticas en memoria para este filtro.`);
    if (sharingPolicies.length > 0) {
      Logger.log(`[ID-096] Detalles de las políticas encontradas: ` + JSON.stringify(sharingPolicies.map(p => ({ type: p.type, name: p.name, sortOrder: p.policyQuery?.sortOrder, hasGroup: !!p.policyQuery?.group, orgUnit: p.policyQuery?.orgUnit }))));
    } else {
      Logger.log(`[ID-096] [WARNING] La API masiva no trajo configuraciones para esta política. Esto puede explicar el retorno NULL o valores por defecto.`);
    }

    let allowNonGoogle = false;
    let isSharingDisallowed = false;
    let rawData = null;

    if (sharingPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(sharingPolicies, "drive_and_docs.external_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Campos modificados a snake_case según la API
        if (valueNode.external_sharing_mode === "DISALLOWED") {
          isSharingDisallowed = true;
        }

        if (valueNode.allow_non_google_invites === true) {
          allowNonGoogle = true;
        }
      }
    }

    let respuestaConcreta;
    let riesgo096, comentario096;

    if (isSharingDisallowed) {
      respuestaConcreta = "No Aplica";
      riesgo096 = "Bajo";
      comentario096 = "El uso compartido externo está completamente deshabilitado, por lo que no se pueden enviar invitaciones a cuentas externas. La postura de seguridad es óptima.";
    } else if (allowNonGoogle) {
      respuestaConcreta = "Habilitado";
      riesgo096 = "Alto";
      comentario096 = "Se permite enviar invitaciones a personas sin cuenta de Google para acceder a archivos de Drive. Esto implica que los archivos se pueden compartir mediante enlaces con PIN temporales, sin la seguridad de autenticación federada de Google, aumentando la superficie de ataque para phishing y acceso no autorizado.";
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo096 = "Bajo";
      comentario096 = "La compartición con personas sin cuenta de Google se encuentra restringida. Esto garantiza que toda colaboración externa pase por el sistema de autenticación federado de Google, manteniendo la trazabilidad y los controles de acceso.";
    }

    Logger.log(`[LOG] Drive Allow Non-Google Invites Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo096}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario096: comentario096,
      riesgo096: riesgo096,
      score096: this.calcularScoreDeRiesgo(riesgo096)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo096: "Medio", score096: 2, comentario096: msg };
  }
}
