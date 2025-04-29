const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class Tarifa extends Model {
    static associate(models) {
      Tarifa.belongsTo(models.UsuarioBasico, {
        foreignKey: 'id_usuario_basico',
        as: 'usuario'
      });
      Tarifa.hasMany(models.ComparacionTarifas, {
        foreignKey: 'id_tarifa_usuario',
        as: 'comparaciones'
      });
    }
  }

  Tarifa.init({
    id_tarifa: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    id_usuario_basico: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'usuario_basico',
        key: 'id_usuario_basico'
      }
    },
    archivo: {
      type: DataTypes.TEXT,
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    fecha_subida: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW
    }
  }, {
    sequelize,
    modelName: 'Tarifa',
    tableName: 'tarifa',
    timestamps: false
  });

  return Tarifa;
};