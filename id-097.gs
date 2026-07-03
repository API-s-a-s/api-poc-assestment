/**
 * Estrategia para auditar si se permite publicar archivos de Google Drive al mundo (Internet).
 * Evalúa la propiedad booleana allow_publishing_files.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.external_sharing
 */
class DriveAllowPublishingFilesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-097", 
        valueKey: "valorPrincipal",
        noteKey: "comentario097",
        riskKey: "riesgo097",
        scoreKey: "score097"
      }
    ];

    super("Drive Allow Publishing Files Audit", configIDs);
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
    Logger.log(`[ID-097] Se encontraron ${sharingPolicies.length} políticas en memoria para este filtro.`);
    if (sharingPolicies.length > 0) {
      Logger.log(`[ID-097] Detalles de las políticas encontradas: ` + JSON.stringify(sharingPolicies.map(p => ({ type: p.type, name: p.name, sortOrder: p.policyQuery?.sortOrder, hasGroup: !!p.policyQuery?.group, orgUnit: p.policyQuery?.orgUnit }))));
    } else {
      Logger.log(`[ID-097] [WARNING] La API masiva no trajo configuraciones para esta política. Esto puede explicar el retorno NULL o valores por defecto.`);
    }

    let allowPublishing = false;
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

        if (valueNode.allow_publishing_files === true) {
          allowPublishing = true;
        }
      }
    }

    let respuestaConcreta;
    let riesgo097, comentario097;

    if (isSharingDisallowed) {
      respuestaConcreta = "No Aplica";
      riesgo097 = "Bajo";
      comentario097 = "El uso compartido externo está completamente deshabilitado, por lo que la publicación no entra en vigor. La postura de seguridad es óptima.";
    } else if (allowPublishing) {
      respuestaConcreta = "Habilitado";
      riesgo097 = "Alto";
      comentario097 = "Se permite a los usuarios publicar archivos de Google Drive de forma pública en internet. Esto representa un riesgo crítico de DLP (Data Loss Prevention), ya que cualquier persona con el enlace puede acceder al contenido sin autenticación.";
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo097 = "Bajo";
      comentario097 = "La publicación de archivos a internet está deshabilitada. Los documentos no pueden ser indexados por motores de búsqueda ni compartidos como páginas web públicas, previniendo la exposición masiva de datos corporativos.";
    }

    Logger.log(`[LOG] Drive Allow Publishing Files Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo097}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario097: comentario097,
      riesgo097: riesgo097,
      score097: this.calcularScoreDeRiesgo(riesgo097)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo097: "Medio", score097: 2, comentario097: msg };
  }
}
