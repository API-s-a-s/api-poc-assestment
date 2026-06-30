/**
 * Estrategia para auditar las configuraciones predeterminadas de Access Checker al compartir enlaces.
 * Evalúa el enum accessCheckerSuggestions (RECIPIENTS_OR_AUDIENCE_OR_PUBLIC, RECIPIENTS_OR_AUDIENCE, RECIPIENTS_ONLY).
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.external_sharing
 */
class DriveAccessCheckerSuggestionsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-099", 
        valueKey: "valorPrincipal",
        noteKey: "comentario099",
        riskKey: "riesgo099",
        scoreKey: "score099"
      }
    ];

    super("Drive Access Checker Suggestions Audit", configIDs);
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

    let accessChecker = "RECIPIENTS_ONLY"; // Lo asumimos como la versión más estricta si no se define.
    let rawData = null;

    if (sharingPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(sharingPolicies, "drive_and_docs.external_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Campo en camelCase según la API real
        if (valueNode.accessCheckerSuggestions) {
          accessChecker = valueNode.accessCheckerSuggestions;
        }
      }
    }

    let respuestaConcreta;
    let riesgo099, comentario099;

    if (accessChecker === "RECIPIENTS_OR_AUDIENCE_OR_PUBLIC") {
      respuestaConcreta = "Destinatarios, Público objetivo o Público Web";
      riesgo099 = "Alto";
      comentario099 = "Access Checker sugiere permitir acceso público cuando los destinatarios no tienen permisos, además de poder compartir de forma genérica con la audiencia. Esta opción es demasiado permisiva y abre la puerta a que los usuarios compartan enlaces al exterior de manera irreflexiva, comprometiendo la postura de protección de la información.";
    } else if (accessChecker === "RECIPIENTS_OR_AUDIENCE") {
      respuestaConcreta = "Destinatarios o Público objetivo";
      riesgo099 = "Medio";
      comentario099 = "Access Checker se limita a sugerir dar acceso a destinatarios específicos o a un público objetivo de la empresa. Reduce la fricción al compartir internamente pero aún permite ampliar la difusión a nivel del dominio o grupos amplios antes de restringir el acceso archivo por archivo.";
    } else { // RECIPIENTS_ONLY u otros no documentados que restrinjan
      respuestaConcreta = "Solo destinatarios";
      riesgo099 = "Bajo";
      comentario099 = "Access Checker sugiere de manera estricta que únicamente los destinatarios directos obtengan acceso al archivo. Esta es la configuración recomendada ya que promueve el principio del mínimo privilegio (Zero Trust), previniendo que los documentos se difundan fuera de un grupo intencionalmente reducido de colaboradores.";
    }

    Logger.log(`[LOG] Drive Access Checker Suggestions Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo099}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario099: comentario099,
      riesgo099: riesgo099,
      score099: this.calcularScoreDeRiesgo(riesgo099)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo099: "Medio", score099: 2, comentario099: msg };
  }
}
