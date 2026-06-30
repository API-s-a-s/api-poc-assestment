/**
 * Estrategia para auditar la presencia de IDs de empleado en el Directorio
 * Utiliza la Admin SDK: Directory API
 * Itera de forma masiva sobre todos los usuarios para validar la viabilidad 
 * de los desafíos de inicio de sesión post-SSO (security.login_challenges).
 */
class EmployeeIdStrategy extends ApiStrategy {
  constructor() {
    // 1. Definimos la matriz con el ID-020 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-020", 
        valueKey: "valorPrincipal",
        noteKey: "comentario020",
        riskKey: "riesgo020",
        scoreKey: "score020"
      }
    ];

    super("Employee ID Population Audit", configIDs);
    
    // El parámetro customer=my_customer es un alias seguro de Google para iterar sobre el propio tenant.
    this.url = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500";
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
      Logger.log(`[ERROR] Employee ID Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR_API",
        riesgo020: "Medio",
        score020: 2,
        comentario020: `Error de lectura en la API Directory. Motivo: ${json.error.message}. Impide auditar el estado del directorio de usuarios.`
      };
    }

    // 2. EXTRACCIÓN MASIVA (PAGINACIÓN OBLIGATORIA)
    let usuarios = json.users || [];
    
    // Si la llamada inicial hecha por la Facade detecta más de 500 usuarios, re-hidratamos todo el directorio.
    if (json.nextPageToken) {
      Logger.log("[INFO] Directorio extenso detectado. Paginando para extraer a todos los usuarios...");
      const todosLosUsuarios = this.fetchPaginated(this.url, "users");
      if (todosLosUsuarios) usuarios = todosLosUsuarios;
    }

    const totalUsuarios = usuarios.length;

    // Manejo de JSON vacío (Dominio sin usuarios listables)
    if (totalUsuarios === 0) {
      Logger.log("[AVISO] La API Directory no retornó ningún usuario.");
      return {
        name: this.name,
        raw: json,
        valorPrincipal: "Sin usuarios",
        riesgo020: "Medio",
        score020: 2,
        comentario020: "No se detectaron usuarios en el directorio. Imposible calcular el índice de IDs corporativos."
      };
    }

    // 3. LÓGICA DE NEGOCIO: VALIDACIÓN DE METADATOS (ID DE EMPLEADO)
    let usuariosConId = 0;

    usuarios.forEach(usuario => {
      const idsExternos = usuario.externalIds || [];
      const organizaciones = usuario.organizations || [];

      // Google Workspace puede almacenar el "Employee ID" en dos nodos distintos 
      // dependiendo de si se creó por UI, API o Google Cloud Directory Sync (GCDS).
      const tieneIdExterno = idsExternos.some(id => id.type === 'organization' && id.value);
      const tieneOrgEmployeeId = organizaciones.some(org => org.employeeId);

      if (tieneIdExterno || tieneOrgEmployeeId) {
        usuariosConId++;
      }
    });

    const porcentajeNum = Math.round((usuariosConId / totalUsuarios) * 100);
    const respuestaConcreta = `${usuariosConId} de ${totalUsuarios} perfiles (${porcentajeNum}%)`;

    // 4. APLICACIÓN DE MATRICES DE RIESGO
    let riesgo020, comentario020;

    if (porcentajeNum === 0) {
      riesgo020 = "Alto";
      comentario020 = "Ningún usuario registrado en el directorio cuenta con el ID corporativo (Employee ID) configurado. Las políticas de desafíos de inicio de sesión post-SSO (Login Challenges) fallarán de forma global al no tener un metadato contra el cual validar identidades anómalas.";
    } else if (porcentajeNum === 100) {
      riesgo020 = "Bajo";
      comentario020 = "CUMPLIMIENTO: La totalidad (100%) de los usuarios tiene su ID de empleado configurado en el directorio. La organización está estructuralmente preparada para disparar con éxito los desafíos de seguridad post-SSO.";
    } else {
      riesgo020 = "Medio";
      comentario020 = `Existe una población fragmentada; solo el ${porcentajeNum}% de los usuarios cuenta con un ID de empleado. Los perfiles carentes de este atributo no podrán ser desafiados de forma segura ante accesos anómalos tras pasar el SSO.`;
    }

    // Log técnico para trazabilidad en consola
    Logger.log(`[RESULTADO ID-020] Completitud de Employee IDs: ${respuestaConcreta} | Riesgo: ${riesgo020}`);

    // 5. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: { totalAnalizados: totalUsuarios, dataExtraida: "Se omitió el JSON crudo por tamaño" },
      valorPrincipal: respuestaConcreta,
      comentario020: comentario020,
      riesgo020: riesgo020,
      score020: this.calcularScoreDeRiesgo(riesgo020)
    };
  }
}