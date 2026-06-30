/**
 * Estrategia para auditar el aprovisionamiento de identidades externas (ej. JumpCloud, Okta, Azure)
 * Utiliza la Admin SDK: Directory API
 * Emplea FieldMasks (fields=...) para descargas ultraligeras y filtrado rápido en memoria.
 */
class ExternalProvisioningStrategy extends ApiStrategy {
  constructor() {
    // 1. Matriz de configuración para el ID-028
    const configIDs = [
      { 
        id: "ID-028", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario028",
        riskKey: "riesgo028",
        scoreKey: "score028"
      }
    ];

    super("External Identity Provisioning Audit", configIDs);

    // 2. MIGRACIÓN ARQUITECTÓNICA CORREGIDA:
    // Se elimina el 'query' inválido. En su lugar, usamos 'fields' para pedir a la API
    // que SOLO construya un JSON con los emails y los IDs externos. Esto evita 
    // desbordamientos de memoria (OOM) en dominios masivos.
    this.url = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500&fields=users(primaryEmail,externalIds),nextPageToken";
    
    this.category = "Identidad y autenticación";
  }

  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  parseResponse(json) {
    // 1. EVALUACIÓN DEFENSIVA DE ERRORES DE API
    if (json.error) {
      Logger.log(`[ERROR API] Provisioning Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR_API",
        riesgo028: "Medio",
        score028: 2,
        comentario028: `Error de lectura en la API Directory: ${json.error.message}. Impide auditar el estado del aprovisionamiento de identidades automatizadas.`
      };
    }

    // 2. EXTRACCIÓN MASIVA (PAGINACIÓN OBLIGATORIA ULTRALIGERA)
    let todosLosUsuarios = json.users || [];

    // Si detecta más de 500 cuentas, hidratamos el resto (rápido gracias a fields)
    if (json.nextPageToken) {
      Logger.log("[INFO] Directorio extenso detectado. Paginando listado ultraligero...");
      const paginados = this.fetchPaginated(this.url, "users");
      if (paginados) todosLosUsuarios = paginados;
    }

    // 3. FILTRADO FORENSE EN MEMORIA
    // Buscamos matemáticamente aquellos que tengan el nodo 'externalIds' mapeado
    const usuariosSincronizados = todosLosUsuarios.filter(user => user.externalIds && user.externalIds.length > 0);
    const totalSincronizados = usuariosSincronizados.length;

    // --- 4. LÓGICA DE NEGOCIO Y MATRICES DE RIESGO ---
    let respuestaConcreta;
    let riesgo028, comentario028;
    const porcentajeSincronizados = Math.round((totalSincronizados / todosLosUsuarios.length) * 100);

    if (porcentajeSincronizados === 100) {
      respuestaConcreta = "Sincronizado (100%)";
      riesgo028 = "Bajo";
      comentario028 = "El 100% de las identidades se aprovisiona y orquesta mediante un Proveedor de Identidad (IdP).";
    } else if (porcentajeSincronizados === 0) {
      respuestaConcreta = "Deshabilitado (0%)";
      riesgo028 = "Alto";
      comentario028 = "Ningún usuario cuenta con identificadores externos.";
    } else {
      respuestaConcreta = `Sincronizado (${porcentajeSincronizados}%)`;
      riesgo028 = "Alto";
      comentario028 = `Solo el ${porcentajeSincronizados}% de las identidades está aprovisionado mediante un IdP.`;
    }

    Logger.log(`[RESULTADO ID-028] Aprovisionamiento Externo: ${respuestaConcreta} | Riesgo: ${riesgo028}`);

    // 5. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      // Retornamos un resumen numérico para no saturar la celda de raw data
      raw: { totalAnalizados: todosLosUsuarios.length, totalSincronizados: totalSincronizados },
      valorPrincipal: respuestaConcreta,
      comentario028: comentario028,
      riesgo028: riesgo028,
      score028: this.calcularScoreDeRiesgo(riesgo028)
    };
  }
}