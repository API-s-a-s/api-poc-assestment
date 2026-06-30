/**
 * Estrategia para auditar la configuración de Certificados S/MIME en Gmail.
 * ID-062: Enfoque de administración de certificados S/MIME.
 */
class GmailSmimeCertificateManagementStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-062", 
        valueKey: "valorPrincipal",
        noteKey: "comentario062",
        riskKey: "riesgo062",
        scoreKey: "score062"
      }
    ];
    super("Gmail S/MIME Certificate Mgmt Audit", configIDs);
    this.category = "Email y DNS";
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

    // Evaluamos el enfoque de S/MIME Certificates (generalmente atado a enhanced_smime_encryption o similar)
    Logger.log(`[DEBUG ID-062] Evaluando certificados S/MIME. Políticas recibidas: ${policies ? policies.length : 0}`);
    const certPolicies = policies.filter(p => p.setting && (
      (p.setting.type || "").endsWith("gmail.enhanced_smime_encryption") || 
      (p.setting.type || "").endsWith("gmail.smime_encryption")
    ));
    Logger.log(`[DEBUG ID-062] Políticas de certificados filtradas encontradas: ${certPolicies.length}`);
    let certMgmtConfigured = false;
    let rawData = null;

    if (certPolicies.length > 0) {
      const rootPolicy = certPolicies[0]; // Extraemos el primero para validación genérica
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-062] Política raíz efectiva encontrada: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-062] valueNode extraído: ${JSON.stringify(valueNode)}`);
        certMgmtConfigured = valueNode.allowUserToUploadCertificates === false || valueNode.enableSmimeEncryption === 'STATUS_ENABLED';
        Logger.log(`[DEBUG ID-062] certMgmtConfigured seteado a: ${certMgmtConfigured}`);
      } else {
        Logger.log(`[DEBUG ID-062] rootPolicy.setting es nulo o indefinido.`);
      }
    } 

    let respuestaConcreta, riesgo062, comentario062;

    if (certMgmtConfigured) {
      respuestaConcreta = "Administrado";
      riesgo062 = "Bajo";
      comentario062 = "Se detectó que el enfoque de administración de certificados S/MIME está configurado y administrado a nivel dominio/usuario. Esto evita que los usuarios manipulen certificados de forma insegura y estandariza la confianza criptográfica.";
    } else {
      // Como no hay evidencia de políticas de certificados, se considera que recae en el usuario o no está usado
      respuestaConcreta = "Deshabilitado";
      riesgo062 = "Medio";
      comentario062 = "No se detectaron políticas avanzadas de administración de certificados S/MIME. Si S/MIME está en uso, la administración de llaves recae en los usuarios finales, lo que incrementa el riesgo de pérdida de llaves privadas o el uso de certificados revocados/no confiables.";
    }

    Logger.log(`[LOG] S/MIME Cert Mgmt Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo062}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario062: comentario062,
      riesgo062: riesgo062,
      score062: this.calcularScoreDeRiesgo(riesgo062)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo062: "Medio", score062: 2, comentario062: msg };
  }
}
