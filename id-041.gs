/**
 * Estrategia para auditar a los usuarios con el rol global de Administrador de Android.
 * Utiliza el Censo en RAM (O(1)) para evitar llamadas redundantes a la API de Directory.
 * Contiene la lógica de negocio para ID-041.
 */
class AndroidAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    const configIDs = [
      { 
        id: "ID-041", 
        valueKey: "valorPrincipal",
        noteKey: "comentario041",
        riskKey: "riesgo041",
        scoreKey: "score041"
      }
    ];

    super("Android Admin Role Audit", configIDs);
    this.roleId = roleId; // Guardamos para la validación en memoria
    this.category = "Administración";
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

  evaluateInMemory(globalContext) {
    const { census } = globalContext;

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    // Basamos el conteo en el total de administradores
    const totalAdmins = census.filter(u => u.isAdmin).length;
    
    if (totalAdmins === 0) {
      return this._buildErrorResponse("El censo no contiene usuarios administradores para auditar.");
    }

    // 1. FILTRAR USUARIOS CON EL ROL ESPECÍFICO A NIVEL GLOBAL
    const adminsList = [];
    
    for (const user of census) {
      // Ignoramos si no tiene el flag de admin o si su arreglo de roles viene vacío
      if (!user.isAdmin || !user.adminRoles || user.adminRoles.length === 0) continue;

      const hasGlobalAndroidAdmin = user.adminRoles.some(role => 
        // Se evalúa coincidencia por ID o por nombre estandarizado ("android admin")
        (role.roleId === this.roleId || role.roleName.toLowerCase().includes("android admin")) 
        && role.scopeType === "CUSTOMER" // Asegura que el poder es sobre toda la empresa (Raíz)
      );
      
      if (hasGlobalAndroidAdmin) {
        adminsList.push(user.email || user.id);
      }
    }
    
    const adminCount = adminsList.length;    
    const porcentajeNum = Math.round((adminCount / totalAdmins) * 100);

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta = `${porcentajeNum}%`;
    let riesgo041, comentario041;

    // Comentarios cortos y directos usando el formato "X de Y"
    if (adminCount > 0) {
      riesgo041 = "Medio";
      comentario041 = `${adminCount} de ${totalAdmins} administradores tienen el rol global de Administrador de Android. Se recomienda delegar por OU (Unidad Organizativa) en lugar de dar acceso global.`;
    } else {
      riesgo041 = "Bajo";
      comentario041 = `${adminCount} de ${totalAdmins} administradores tienen el rol global de Administrador de Android.`;
    }

    // Trazabilidad técnica para la consola
    Logger.log(`[LOG] Android Admin Audit (In-Memory): Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo041}`);
    if (adminCount > 0) {
      Logger.log(`[ID-041] Cuentas con el rol de Administrador de Android Global: ${adminsList.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario041: comentario041,
      riesgo041: riesgo041,
      score041: this.calcularScoreDeRiesgo(riesgo041)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-041] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo041: "Medio",
      score041: 2,
      comentario041: msg
    };
  }
}