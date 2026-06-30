/**
 * Estrategia para auditar si se exigen desafíos de inicio de sesión adicionales (Post-SSO).
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-018
 */
class PostSsoLoginPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-018 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-018", 
        valueKey: "valorPrincipal",
        noteKey: "comentario018",
        riskKey: "riesgo018",
        scoreKey: "score018"
      }
    ];
    super("Post-SSO Login Challenges Audit", configIDs);
    
    // Filtro con el operador && para la política de desafíos de login
    const filter = `customer=="customers/${customerId}" && setting.type=="security.login_challenges"`;
    this.url = `https://cloudidentity.googleapis.com/v1beta1/policies?filter=${encodeURIComponent(filter)}`;
    this.category = "Identidad y autenticación";
  }
  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
  }
  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return "";
  }
  parseResponse(json) {
    // 1. EVALUACIÓN EN CASO DE ERROR DE API
    if (json.error) {
      Logger.log(`[ERROR] Login Challenges Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo018: "Medio",
        score018: 2,
        comentario018: "Error de lectura vía API Cloud Identity que impide validar técnicamente el estado de la política de desafíos de inicio de sesión post-SSO."
      };
    }
    const policies = json.policies || [];
    // Filtramos para encontrar políticas que tengan habilitados los desafíos Post-SSO
    const activePostSsoPolicies = policies.filter(policy => {
      if (policy.setting) {
        const configNode = policy.setting.loginChallenges || policy.setting.value || policy.setting;
        
        // Usamos una búsqueda segura dentro del nodo de configuración
        const nodeStr = JSON.stringify(configNode).toLowerCase();
        
        // Verificamos presencia de indicadores Post-SSO y que no estén explícitamente en false
        const tieneIndicador = nodeStr.includes('post_sso') || 
                               nodeStr.includes('postsso') || 
                               configNode.isPostSsoChallengesEnabled === true;
        
        const noEstaApagado = !nodeStr.includes('"postsso":false') && 
                              !nodeStr.includes('"postssochallengesenabled":false');
        return tieneIndicador && noEstaApagado;
      }
      return false;
    });
    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo018, comentario018;
    if (activePostSsoPolicies.length > 0) {
      // Caso 1: La verificación adicional post-SSO está activa
      respuestaConcreta = "Habilitado";
      riesgo018 = "Bajo";
      comentario018 = "La política exige a los usuarios completar desafíos de inicio de sesión adicionales en Google Workspace tras haberse autenticado a través de un proveedor de identidad externo (SSO).";
      
    } else if (policies.length === 0) {
      // Caso 2: El JSON vino vacío (sin configuración de desafíos)
      respuestaConcreta = "Deshabilitado";
      riesgo018 = "Medio";
      comentario018 = "La consola no tiene configurada ninguna directiva que exija desafíos de inicio de sesión adicionales en Google Workspace posteriores a la autenticación mediante SSO.";
      
    } else {
      // Caso 3: La política existe pero no tiene el Post-SSO activo
      // Volcamos el JSON para inspección manual
      respuestaConcreta = JSON.stringify(json);
      riesgo018 = "Medio";
      comentario018 = "Existe una directiva de desafíos de inicio de sesión configurada, pero la opción específica de verificación adicional post-SSO se encuentra inactiva o denegada explícitamente.";
    }
    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Post-SSO Audit: Resultado final -> ${respuestaConcreta} | Riesgo: ${riesgo018}`);
    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario018: comentario018,
      riesgo018: riesgo018,
      score018: this.calcularScoreDeRiesgo(riesgo018)
    };
  }
}
