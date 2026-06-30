/**
 * Estrategia para auditar a los usuarios con el rol global de Administrador de Dispositivos Móviles.
 * Utiliza el Censo en RAM (O(1)) para evitar llamadas redundantes a la API de Directory.
 * Contiene la lógica de negocio para ID-039.
 */
class MobileAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    const configIDs = [
      { 
        id: "ID-039", 
        valueKey: "valorPrincipal",
        noteKey: "comentario039",
        riskKey: "riesgo039",
        scoreKey: "score039"
      }
    ];

    super("Mobile Admin Role Assignments Audit", configIDs);
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

    const totalAdmins = census.filter(u => u.isAdmin).length;
    
    if (totalAdmins === 0) {
      return this._buildErrorResponse("El censo no contiene usuarios administradores para auditar.");
    }

    // 1. FILTRAR USUARIOS CON EL ROL ESPECÍFICO A NIVEL GLOBAL
    const adminsList = [];
    
    for (const user of census) {
      // Ignoramos si no tiene el flag de admin o si su arreglo de roles viene vacío
      if (!user.isAdmin || !user.adminRoles || user.adminRoles.length === 0) continue;

      const hasGlobalMobileAdmin = user.adminRoles.some(role => 
        // Criterio primario: roleId numérico real (resuelto dinámicamente por AuthService)
        // Criterio secundario (fallback): coincidencia por nombre del sistema
        (role.roleId === this.roleId || role.roleName.toLowerCase().includes("mobile admin")) 
        && role.scopeType === "CUSTOMER" // Asegura que el poder es sobre toda la empresa (Raíz)
      );
      
      if (hasGlobalMobileAdmin) {
        adminsList.push(user.email || user.id);
      }
    }
    
    const adminCount = adminsList.length;    
    const porcentajeNum = Math.round((adminCount / totalAdmins) * 100);

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo039, comentario039;

    respuestaConcreta = `${porcentajeNum}%`;

    if (adminCount > 0) {
      riesgo039 = "Medio";
      comentario039 = `ATENCIÓN: ${adminCount} de ${totalAdmins} administradores tienen el rol global de Administrador de Dispositivos Móviles (MDM). Este rol permite configurar políticas de seguridad para móviles (incluyendo Android Enterprise y Apple MDM) en todo el dominio. Se recomienda auditar si requieren acceso global o solo por Unidad Organizativa.`;
    } else {
      riesgo039 = "Bajo";
      comentario039 = `Postura segura. ${adminCount} de ${totalAdmins} administradores tienen el rol global de Administrador de Dispositivos Móviles. La gestión de MDM no está delegada globalmente de forma excesiva.`;
    }

    // Trazabilidad técnica para la consola
    Logger.log(`[LOG] Mobile Admin Audit (In-Memory): Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo039}`);
    if (adminCount > 0) {
      Logger.log(`[ID-039] Cuentas con el rol de Administrador de Dispositivos Móviles: ${adminsList.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario039: comentario039,
      riesgo039: riesgo039,
      score039: this.calcularScoreDeRiesgo(riesgo039)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-039] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo039: "Medio",
      score039: 2,
      comentario039: msg
    };
  }
}